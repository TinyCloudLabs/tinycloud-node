//! Scan all production items, including those following test-only items.
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::path::{Path, PathBuf};
use syn::{
    ext::IdentExt,
    visit::{self, Visit},
    Attribute, Item,
};

fn ident_name(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

fn normalized_tokens(tokens: TokenStream) -> TokenStream {
    tokens
        .into_iter()
        .map(|token| match token {
            TokenTree::Ident(ident) => TokenTree::Ident(ident.unraw()),
            TokenTree::Group(group) => {
                let mut normalized =
                    proc_macro2::Group::new(group.delimiter(), normalized_tokens(group.stream()));
                normalized.set_span(group.span());
                TokenTree::Group(normalized)
            }
            other => other,
        })
        .collect()
}

fn canonical_tokens(value: &impl ToTokens) -> String {
    normalized_tokens(value.to_token_stream()).to_string()
}

fn source_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        canonical_tokens(attr.path()) == "cfg"
            && matches!(&attr.meta, syn::Meta::List(list) if canonical_tokens(&list.tokens) == "test")
    })
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        _ => &[],
    }
}

fn resolver_entry(name: &str) -> bool {
    matches!(
        name,
        "verify_signature"
            | "resolve"
            | "resolve_with"
            | "resolve_representation"
            | "resolve_method_representation"
            | "resolve_into_any_verification_method"
    ) || name == "dereference"
        || name.starts_with("dereference_")
        || name.starts_with("resolve_verification_method")
        || name.starts_with("into_vm_resolver")
}

fn raw_resolver_ident(name: &str) -> bool {
    matches!(
        name,
        "AnyDidMethod"
            | "DID_METHODS"
            | "DIDWeb"
            | "DIDTz"
            | "DIDION"
            | "DIDEthr"
            | "VerificationMethodDIDResolver"
            | "VerificationParameters"
            | "did_web"
            | "did_tz"
            | "did_ion"
            | "did_ethr"
    )
}

fn network_did_module(name: &str) -> bool {
    matches!(name, "web" | "tz" | "ion" | "ethr")
}

#[derive(Default)]
struct Guard {
    file: String,
    function: String,
    violations: Vec<String>,
    helper_calls: usize,
    test_modules: Vec<PathBuf>,
    module_dir: PathBuf,
}

impl Guard {
    fn new(file: &str) -> Self {
        let path = Path::new(file);
        let mut module_dir = path.parent().unwrap().to_path_buf();
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if !matches!(stem, "lib" | "main" | "mod") {
            module_dir.push(stem);
        }
        Self {
            file: file.into(),
            module_dir,
            ..Self::default()
        }
    }

    fn allowed(&self, call: &syn::ExprMethodCall) -> bool {
        let expression = canonical_tokens(call);
        // Exact pre-existing calls only: storage config, byte ranges, pinned
        // webhook DNS, share authority, and DID reference absolutization.
        // Manifest::resolve is the existing non-UCAN, caller-supplied resolver
        // API. Its single call is narrowly exempted; new calls still fail.
        matches!((self.file.as_str(), self.function.as_str(), expression.as_str()),
            ("tinycloud-core/src/manifest.rs", "resolve", "resolver . resolve (id . did ())")
            | ("tinycloud-core/src/manifest.rs", "id_from_vm", "r . resolve (did)")
            | ("tinycloud-core/src/share_email/ports.rs", "resolve_exact", "self . resolve (policy , delegation)")
            | ("tinycloud-core/src/storage/memory.rs", "read_range", "range . resolve (total_size)")
            | ("tinycloud-node-server/src/storage/file_system.rs", "read_range", "range . resolve (total_size)")
            | ("tinycloud-node-server/src/storage/s3.rs", "parse_content_range", "ByteRangeSpec :: Inclusive { start , end } . resolve (total_size)")
            // TC-887: at-rest Range mapping resolves an HTTP byte range against the plaintext length.
            | ("tinycloud-core/src/at_rest/stream.rs", "map_range", "spec . resolve (self . plaintext_len ())")
            | ("tinycloud-node-server/src/lib.rs", "resolve_runtime_config", "resolved . storage . resolve ()")
            | ("tinycloud-node-server/src/runtime.rs", "serve_config_figment", "resolved . storage . resolve ()")
            | ("tinycloud-node-server/src/runtime.rs", "launch_with_figment", "tinycloud_config . storage . resolve ()")
            | ("tinycloud-node-server/src/node_control/service.rs", "effective_config", "config . storage . resolve ()")
            | ("tinycloud-node-server/src/node_control/control.rs", "spawn_control_plane", "effective_config . storage . resolve ()")
            | ("tinycloud-node-server/src/node_control/control.rs", "effective_public_config", "config . storage . resolve ()")
            | ("tinycloud-node-server/src/webhook_dispatcher.rs", "pinned_client", "Client :: builder () . timeout (self . timeout) . redirect (Policy :: none ()) . resolve (host , address)")
        )
    }

    fn auth_resolver_import(&self, item: &syn::ItemUse) -> bool {
        self.file == "tinycloud-auth/src/resolver.rs"
            && canonical_tokens(item) == "use ssi :: dids :: AnyDidMethod ;"
    }

    fn auth_resolver_definition(&self, mac: &syn::Macro) -> bool {
        // Exempt only the existing offline-generation registry declaration,
        // never the rest of resolver.rs or another lazy_static body.
        self.file == "tinycloud-auth/src/resolver.rs"
            && canonical_tokens(&mac.path) == "lazy_static :: lazy_static"
            && canonical_tokens(&mac.tokens)
                == "pub static ref DID_METHODS : AnyDidMethod = AnyDidMethod :: default () ;"
    }

    fn offline_cacao_verification(&self, call: &syn::ExprMethodCall) -> bool {
        // CACAO's argument-free SIWE verification is offline. Pin these
        // existing expressions; never exempt a file, function, or receiver.
        matches!(
            (
                self.file.as_str(),
                self.function.as_str(),
                canonical_tokens(call).as_str()
            ),
            (
                "tinycloud-core/src/models/delegation.rs",
                "verify",
                "cacao . verify ()"
            ) | (
                "tinycloud-core/src/models/revocation.rs",
                "process",
                "c . verify ()"
            ) | (
                "tinycloud-node-server/src/policy_v3.rs",
                "authenticate_account_owner",
                "cacao . verify ()"
            ) | (
                "tinycloud-node-server/src/share_v2.rs",
                "verify_delegation_signature",
                "cacao . verify ()"
            )
        )
    }

    fn scan_macro(&mut self, tokens: TokenStream) {
        // syn leaves macro bodies opaque. Inspect their tokens too, so a raw
        // resolver call inside a production macro cannot evade the guard.
        let tokens: Vec<_> = tokens.into_iter().collect();
        for window in tokens.windows(4) {
            if matches!(&window[0], TokenTree::Ident(ident) if ident_name(ident) == "dids")
                && matches!(&window[1], TokenTree::Punct(punct) if punct.as_char() == ':')
                && matches!(&window[2], TokenTree::Punct(punct) if punct.as_char() == ':')
            {
                match &window[3] {
                    TokenTree::Ident(ident) if network_did_module(&ident_name(ident)) => {
                        self.violations
                            .push(format!("network DID module dids::{ident} in macro"));
                    }
                    TokenTree::Group(_) => {
                        // Preserve grouped import paths such as
                        // dids::{web as resolver, key::{self, DIDKey}}.
                        if let Ok(tree) = syn::parse2(window.iter().cloned().collect()) {
                            self.scan_use_tree(&tree, false);
                        }
                    }
                    _ => {}
                }
            }
        }
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.scan_macro(group.stream()),
                TokenTree::Ident(ident) => {
                    let name = ident_name(&ident);
                    if raw_resolver_ident(&name) || resolver_entry(&name) {
                        self.violations
                            .push(format!("resolver token {name} in macro"));
                    }
                }
                _ => {}
            }
        }
    }

    fn scan_use_tree(&mut self, tree: &syn::UseTree, parent_is_dids: bool) {
        match tree {
            syn::UseTree::Path(path) => {
                self.check_module(&path.ident, parent_is_dids);
                self.scan_use_tree(&path.tree, ident_name(&path.ident) == "dids");
            }
            syn::UseTree::Name(name) => self.check_module(&name.ident, parent_is_dids),
            syn::UseTree::Rename(rename) => self.check_module(&rename.ident, parent_is_dids),
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.scan_use_tree(tree, parent_is_dids);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    fn check_module(&mut self, ident: &syn::Ident, parent_is_dids: bool) {
        if parent_is_dids && network_did_module(&ident_name(ident)) {
            self.violations
                .push(format!("network DID module dids::{ident}"));
        }
    }
}

impl<'ast> Visit<'ast> for Guard {
    fn visit_item(&mut self, item: &'ast Item) {
        if test_only(item_attrs(item)) {
            if let Item::Mod(module) = item {
                if module.content.is_none() {
                    let dir = self.module_dir.join(ident_name(&module.ident));
                    self.test_modules.push(dir.with_extension("rs"));
                    self.test_modules.push(dir.join("mod.rs"));
                }
            }
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let previous = self.module_dir.clone();
        self.module_dir.push(ident_name(&module.ident));
        visit::visit_item_mod(self, module);
        self.module_dir = previous;
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = match item {
            syn::ImplItem::Const(x) => &x.attrs,
            syn::ImplItem::Fn(x) => &x.attrs,
            syn::ImplItem::Type(x) => &x.attrs,
            syn::ImplItem::Macro(x) => &x.attrs,
            _ => return,
        };
        if !test_only(attrs) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = match item {
            syn::TraitItem::Const(x) => &x.attrs,
            syn::TraitItem::Fn(x) => &x.attrs,
            syn::TraitItem::Type(x) => &x.attrs,
            syn::TraitItem::Macro(x) => &x.attrs,
            _ => return,
        };
        if !test_only(attrs) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        self.function = ident_name(&signature.ident);
        visit::visit_signature(self, signature);
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if raw_resolver_ident(&ident_name(ident)) {
            self.violations.push(format!("raw resolver {ident}"));
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        for (parent, child) in path.segments.iter().zip(path.segments.iter().skip(1)) {
            self.check_module(&child.ident, ident_name(&parent.ident) == "dids");
        }
        visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if self.auth_resolver_import(item) {
            return;
        }
        self.scan_use_tree(&item.tree, false);
        visit::visit_item_use(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // DID generation is offline and does not resolve an issuer. Visit its
        // arguments, but exempt only the DID_METHODS.generate receiver.
        if ident_name(&call.method) == "generate"
            && matches!(&*call.receiver,
            syn::Expr::Path(path) if path.path.segments.last().is_some_and(|s| ident_name(&s.ident) == "DID_METHODS"))
        {
            for argument in &call.args {
                self.visit_expr(argument);
            }
            return;
        }
        if !self.offline_cacao_verification(call)
            && resolver_entry(&ident_name(&call.method))
            && !self.allowed(call)
        {
            self.violations.push(call.to_token_stream().to_string());
        }
        // Ordinary verify() also serves fixed-key cryptography; any resolver
        // types, factories, or calls in its receiver/arguments are still visited.
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let name = ident_name(&path.path.segments.last().unwrap().ident);
            // Explicit non-DID function paths; aliases and unqualified raw
            // resolve calls still fail. These operate on profile paths or
            // stored SQL/DuckDB publication names, never on issuer DIDs.
            let function_path = canonical_tokens(path);
            let non_did = matches!(
                (self.file.as_str(), function_path.as_str()),
                (
                    "tinycloud-node-server/src/node_control/paths.rs",
                    "ProfilePaths :: resolve"
                ) | (
                    "tinycloud-node-server/src/routes/mod.rs",
                    "database_migration :: resolve"
                ) | (
                    "tinycloud-node-server/src/share_email.rs",
                    "tinycloud_core :: database_migration :: resolve"
                )
            );
            if resolver_entry(&name) && !non_did {
                self.violations.push(call.to_token_stream().to_string());
            }
            if matches!(
                name.as_str(),
                "verify_ucan_signature" | "verify_ucan_revocation_signature"
            ) {
                self.helper_calls += 1;
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if self.auth_resolver_definition(mac) {
            return;
        }
        self.scan_macro(mac.tokens.clone());
    }
}

#[test]
fn ucan_resolution_has_one_production_entry_point() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for dir in [
        "tinycloud-core/src",
        "tinycloud-node-server/src",
        "tinycloud-auth/src",
    ] {
        source_files(&root.join(dir), &mut files);
    }
    let mut scans = Vec::new();
    for path in files {
        let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
        if relative == "tinycloud-core/src/did_resolution.rs" {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let ast =
            syn::parse_file(&source).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let mut guard = Guard::new(relative);
        guard.visit_file(&ast);
        scans.push(guard);
    }
    let test_modules: Vec<_> = scans.iter().flat_map(|scan| &scan.test_modules).collect();
    let mut calls = 0;
    for scan in &scans {
        if test_modules
            .iter()
            .any(|path| Path::new(&scan.file).starts_with(path))
        {
            continue;
        }
        assert!(
            scan.violations.is_empty(),
            "UCAN resolver bypass in {}: {:?}",
            scan.file,
            scan.violations
        );
        calls += scan.helper_calls;
    }
    assert!(
        calls >= 5,
        "expected at least five production helper calls, found {calls}"
    );
}

#[test]
fn only_test_items_are_excluded_and_all_raw_entry_points_are_checked() {
    let source = r#"
        #[cfg(test)] extern crate tokio;
        #[cfg(test)] mod tests { fn offline() { AnyDidMethod::default().resolve(did); } }
        struct Example;
        impl Example {
            #[cfg(test)] fn fixture() { DID_METHODS.resolve(did); }
            fn production() {
                let resolver = AnyDidMethod::default();
                resolver.resolve(did);
                resolver.resolve_representation(did, options);
                resolver.resolve_with(did, options);
                resolver.resolve_into_any_verification_method(did);
                resolver.dereference(url);
                resolver.dereference_with(url, options);
                DIDResolver::resolve(&resolver, did);
                DID_METHODS.resolve(did);
                wrapper!(resolver.dereference(url));
                verify_ucan_signature(ucan);
            }
        }
        #[cfg(test)] fn other_fixture() { DID_METHODS.resolve(did); }
        fn later_production() { resolver.dereference(url); }
    "#;
    let mut guard = Guard::new("fixture.rs");
    guard.visit_file(&syn::parse_file(source).unwrap());
    assert_eq!(guard.helper_calls, 1);
    assert_eq!(guard.violations.len(), 12, "{:?}", guard.violations);

    let mut guard = Guard::new("tinycloud-core/src/storage/memory.rs");
    guard.visit_file(&syn::parse_file("fn read_range() { range.resolve(total_size); }").unwrap());
    assert!(guard.violations.is_empty());
    guard.visit_file(&syn::parse_file("fn other() { range.resolve(total_size); }").unwrap());
    assert_eq!(guard.violations.len(), 1);
}

fn scan_fixture(code: &str) -> Guard {
    let mut guard = Guard::new("fixture.rs");
    guard.visit_file(&syn::parse_file(code).unwrap());
    guard
}

#[test]
fn raw_identifiers_cannot_hide_resolver_names() {
    for source in [
        "async fn production() { u.r#verify_signature(&dids::r#AnyDidMethod::default()).await; }",
        "async fn production() { dids::r#DIDWeb.r#into_vm_resolver::<Method>().r#resolve_verification_method_with(id, None, options).await; }",
        "async fn production() { adapter.r#resolve(did).await; adapter.r#dereference_with(url, options).await; }",
        "async fn production() { Adapter::r#into_vm_resolver_with(adapter, options); }",
        "wrapper!(dids::r#DIDTz.r#into_vm_resolver::<Method>());",
        "use provider::r#dids::r#web as Renamed;",
        "use provider::r#dids::{r#tz as Renamed, key::DIDKey};",
        "type Adapter = provider::r#dids::r#ion::Resolver;",
        "wrapper!(provider::r#dids::r#ethr::Resolver);",
        "wrapper!(use provider::r#dids::{r#web as Renamed});",
    ] {
        let raw = scan_fixture(source);
        let ordinary = scan_fixture(&source.replace("r#", ""));
        assert!(!raw.violations.is_empty(), "raw identifier bypass: {source}");
        assert_eq!(raw.violations.len(), ordinary.violations.len(), "{source}");
    }
    for ident in [
        "AnyDidMethod",
        "DID_METHODS",
        "DIDWeb",
        "DIDTz",
        "DIDION",
        "DIDEthr",
        "VerificationMethodDIDResolver",
        "VerificationParameters",
        "did_web",
        "did_tz",
        "did_ion",
        "did_ethr",
    ] {
        for source in [
            format!("use provider::r#{ident} as Renamed;"),
            format!("type Adapter = provider::r#{ident};"),
            format!("wrapper!(provider::r#{ident});"),
        ] {
            assert!(!scan_fixture(&source).violations.is_empty(), "{source}");
        }
    }
}

#[test]
fn raw_identifiers_preserve_exact_offline_and_test_exceptions() {
    let source = r##"
        #[r#cfg(r#test)] mod r#tests { fn fixture() { r#AnyDidMethod::default(); } }
        fn production() {
            r#DID_METHODS.r#generate(&key, pattern);
            r#verify_ucan_signature(ucan);
            wrapper!("r#DIDWeb r#into_vm_resolver r#dids::r#web");
        }
    "##;
    let guard = scan_fixture(source);
    assert!(guard.violations.is_empty(), "{:?}", guard.violations);
    assert_eq!(guard.helper_calls, 1);
    let mut guard = Guard::new("tinycloud-core/src/storage/memory.rs");
    guard.visit_file(
        &syn::parse_file("fn r#read_range() { r#range.r#resolve(r#total_size); }").unwrap(),
    );
    assert!(guard.violations.is_empty(), "{:?}", guard.violations);
    guard.visit_file(&syn::parse_file("fn other() { r#range.r#resolve(r#total_size); }").unwrap());
    assert_eq!(guard.violations.len(), 1);

    let guard = scan_fixture("fn production() { r#DID_METHODS.r#generate(r#DIDWeb, pattern); }");
    assert!(
        !guard.violations.is_empty(),
        "generation arguments were exempted"
    );
}

#[test]
fn auth_registry_exception_cannot_hide_another_resolver_call() {
    let registry = include_str!("../../tinycloud-auth/src/resolver.rs");
    for source in [
        registry.to_string(),
        registry
            .replace("AnyDidMethod", "r#AnyDidMethod")
            .replace("DID_METHODS", "r#DID_METHODS"),
    ] {
        let mut guard = Guard::new("tinycloud-auth/src/resolver.rs");
        guard.visit_file(&syn::parse_file(&source).unwrap());
        assert!(guard.violations.is_empty(), "{:?}", guard.violations);
        let mut guard = Guard::new("tinycloud-auth/src/other.rs");
        guard.visit_file(&syn::parse_file(&source).unwrap());
        assert!(
            !guard.violations.is_empty(),
            "registry exception spread to another file"
        );
    }
    for source in [
        format!("{registry}\nasync fn verify_with_any(u: &Ucan) {{ u.verify_signature(&*DID_METHODS).await; }}"),
        registry.replace("AnyDidMethod::default()", "AnyDidMethod::default().resolve(did)"),
        registry.replace("pub static ref", "static ref"),
        format!("{registry}\nwrapper!(DID_METHODS.resolve(did));"),
    ] {
        let mut guard = Guard::new("tinycloud-auth/src/resolver.rs");
        guard.visit_file(&syn::parse_file(&source).unwrap());
        assert!(!guard.violations.is_empty(), "auth bypass: {source}");
    }
}

#[test]
fn offline_cacao_exceptions_are_exact_and_do_not_hide_claims_resolvers() {
    for (file, function, receiver) in [
        ("tinycloud-core/src/models/delegation.rs", "verify", "cacao"),
        ("tinycloud-core/src/models/revocation.rs", "process", "c"),
        (
            "tinycloud-node-server/src/policy_v3.rs",
            "authenticate_account_owner",
            "cacao",
        ),
        (
            "tinycloud-node-server/src/share_v2.rs",
            "verify_delegation_signature",
            "cacao",
        ),
    ] {
        let mut guard = Guard::new(file);
        guard.function = function.into();
        let call: syn::ExprMethodCall = syn::parse_str(&format!("{receiver}.verify()")).unwrap();
        assert!(guard.offline_cacao_verification(&call));
        guard.visit_expr_method_call(&call);
        assert!(guard.violations.is_empty());
        let call: syn::ExprMethodCall = syn::parse_str(&format!(
            "{receiver}.verify(VerificationParameters::from_resolver(DIDWeb.into_vm_resolver::<Method>()))"
        )).unwrap();
        assert!(!guard.offline_cacao_verification(&call));
        guard.visit_expr_method_call(&call);
        assert!(
            !guard.violations.is_empty(),
            "CACAO exception hid a claims resolver"
        );
        guard.function = "another_function".into();
        let call = syn::parse_str(&format!("{receiver}.verify()")).unwrap();
        assert!(!guard.offline_cacao_verification(&call));
    }
}

#[test]
fn vm_and_claims_bypasses_and_existing_raw_spellings_are_refused() {
    // Review 5513828343's four surviving spellings and two already killed
    // spellings. Parsing these fixtures never invokes a resolver or claims verifier.
    let cases = [
        ("web VM", "DIDWeb.into_vm_resolver::<AnyMethod>().resolve_verification_method_with(id, None, options).await;"),
        ("tz VM", "DIDTz::default().into_vm_resolver::<AnyMethod>().resolve_verification_method_with(id, None, options).await;"),
        ("web claims", "jws.verify(VerificationParameters::from_resolver(DIDWeb.into_vm_resolver::<AnyJwkMethod>())).await;"),
        ("tz claims", "jws.verify(VerificationParameters::from_resolver(DIDTz::default().into_vm_resolver::<AnyJwkMethod>())).await;"),
        ("raw signature", "u.verify_signature(&AnyDidMethod::default()).await;"),
        ("raw resolve", "DID_METHODS.resolve(d).await;"),
    ];
    for (name, expression) in cases {
        let production = format!("async fn production() {{ {expression} }}");
        let guard = scan_fixture(&production);
        assert!(!guard.violations.is_empty(), "{name} bypass survived");
        let test_only = format!("#[cfg(test)] mod fixture {{ {production} }}");
        assert!(
            scan_fixture(&test_only).violations.is_empty(),
            "{name} test fixture was scanned"
        );
    }
}

#[test]
fn vm_method_families_are_refused_without_concrete_type_names() {
    for expression in [
        "adapter.into_vm_resolver::<Method>();",
        "adapter.into_vm_resolver_with::<Method>(options);",
        "adapter.resolve_verification_method(id).await;",
        "adapter.resolve_verification_method_with(id, None, options).await;",
        "DIDResolver::into_vm_resolver::<Method>(adapter);",
        "DIDResolver::into_vm_resolver_with::<Method>(adapter, options);",
        "VerificationMethodResolver::resolve_verification_method_with(&adapter, id, None, options).await;",
        "wrapper!(adapter.into_vm_resolver_with::<Method>(options));",
        "wrapper!(adapter.resolve_verification_method_with(id, None, options));",
    ] {
        let guard = scan_fixture(&format!("async fn production() {{ {expression} }}"));
        assert!(!guard.violations.is_empty(), "method bypass survived: {expression}");
    }
}

#[test]
fn network_resolver_imports_paths_and_claims_parameters_are_refused() {
    for ident in [
        "DIDWeb",
        "DIDTz",
        "DIDION",
        "DIDEthr",
        "VerificationMethodDIDResolver",
        "VerificationParameters",
        "did_web",
        "did_tz",
        "did_ion",
        "did_ethr",
    ] {
        for source in [
            format!("use provider::{ident} as Renamed;"),
            format!("type Adapter = provider::{ident};"),
            format!("wrapper!(provider::{ident});"),
        ] {
            assert!(
                !scan_fixture(&source).violations.is_empty(),
                "identifier bypass survived: {source}"
            );
        }
    }
    for module in ["web", "tz", "ion", "ethr"] {
        for source in [
            format!("use provider::dids::{module} as Renamed;"),
            format!("use provider::dids::{{{module} as Renamed, key::DIDKey}};"),
            format!("use provider::dids::{{{module}::*, key::DIDKey}};"),
            format!("type Adapter = provider::dids::{module}::Resolver;"),
            format!("wrapper!(provider::dids::{module}::Resolver);"),
            format!("wrapper!(use provider::dids::{{{module} as Renamed, key::DIDKey}});"),
        ] {
            assert!(
                !scan_fixture(&source).violations.is_empty(),
                "module bypass survived: {source}"
            );
        }
    }
}

#[test]
fn non_did_module_names_comments_and_strings_remain_allowed() {
    let source = r#"
        // DIDWeb.into_vm_resolver::<AnyMethod>() is documentation, not a call.
        use provider::{web, tz, ion, ethr};
        use provider::dids::{key::web as key_web, pkh};
        fn production() {
            let _description = "VerificationParameters and provider::dids::web";
            web::request();
            tz::offset();
            ion::charge();
            ethr::lookup();
            wrapper!(provider::dids::key::web);
            wrapper!(use provider::dids::{key::web as key_web});
        }
    "#;
    let guard = scan_fixture(source);
    assert!(guard.violations.is_empty(), "{:?}", guard.violations);
}
