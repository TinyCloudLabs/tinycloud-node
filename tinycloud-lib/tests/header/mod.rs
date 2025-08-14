use tinycloud_lib::authorization::{
    HeaderEncode, TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation,
};
use ssi::ucan::{Ucan, Payload};
use ssi::dids::{DIDBuf, DIDURLBuf};
use ssi::claims::jwt::NumericDate;
use ssi::jwk::JWK;
use cacaos::siwe_cacao::SiweCacao;
use std::str::FromStr;

fn create_test_jwk() -> JWK {
    JWK::generate_ed25519().expect("Failed to generate test key")
}

fn create_test_ucan() -> Ucan {
    let jwk = create_test_jwk();
    let payload = Payload {
        issuer: DIDURLBuf::from_str("did:key:test#key").unwrap(),
        audience: DIDBuf::from_str("did:key:test").unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds(9999999999.0).unwrap(),
        nonce: Some("test-nonce".to_string()),
        facts: None,
        proof: vec![],
        attenuation: ucan_capabilities_object::Capabilities::new(),
    };
    
    payload.sign(jwk.get_algorithm().unwrap_or_default(), &jwk).unwrap()
}

fn create_test_cacao() -> SiweCacao {
    // Create a minimal test SiweCacao
    // This is a simplified version - in practice you'd create this properly
    let payload = serde_json::json!({
        "domain": "example.com",
        "address": "0x1234567890123456789012345678901234567890",
        "statement": "Test statement",
        "uri": "https://example.com",
        "version": "1",
        "chainId": 1,
        "nonce": "test-nonce",
        "issuedAt": "2023-01-01T00:00:00.000Z"
    });
    
    // For testing purposes, create a minimal SiweCacao
    // In practice, this would be properly constructed with signatures
    serde_json::from_value(serde_json::json!({
        "h": {
            "t": "caip122"
        },
        "p": payload,
        "s": {
            "t": "eip191",
            "s": "0x" + "0".repeat(130) // dummy signature
        }
    })).expect("Failed to create test cacao")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ucan_delegation_roundtrip() {
        let ucan = create_test_ucan();
        let delegation = TinyCloudDelegation::Ucan(Box::new(ucan));
        
        let encoded = delegation.encode().expect("Failed to encode delegation");
        assert!(encoded.contains('.'), "UCAN should contain dots");
        
        let (decoded, bytes) = TinyCloudDelegation::decode(&encoded).expect("Failed to decode delegation");
        
        match decoded {
            TinyCloudDelegation::Ucan(_) => {}, // Expected
            TinyCloudDelegation::Cacao(_) => panic!("Expected Ucan, got Cacao"),
        }
        
        assert_eq!(encoded.as_bytes(), bytes);
    }

    #[test]
    fn test_cacao_delegation_roundtrip() {
        let cacao = create_test_cacao();
        let delegation = TinyCloudDelegation::Cacao(Box::new(cacao));
        
        let encoded = delegation.encode().expect("Failed to encode delegation");
        assert!(!encoded.contains('.'), "Cacao should not contain dots");
        
        let (decoded, bytes) = TinyCloudDelegation::decode(&encoded).expect("Failed to decode delegation");
        
        match decoded {
            TinyCloudDelegation::Cacao(_) => {}, // Expected
            TinyCloudDelegation::Ucan(_) => panic!("Expected Cacao, got Ucan"),
        }
        
        // For Cacao, bytes should be the decoded base64, not the original string
        assert_ne!(encoded.as_bytes(), bytes);
    }

    #[test]
    fn test_invocation_roundtrip() {
        let ucan = create_test_ucan();
        
        let encoded = ucan.encode().expect("Failed to encode invocation");
        assert!(encoded.contains('.'), "UCAN should contain dots");
        
        let (decoded, bytes) = TinyCloudInvocation::decode(&encoded).expect("Failed to decode invocation");
        
        // Basic validation that we got a Ucan back
        assert_eq!(encoded.as_bytes(), bytes);
    }

    #[test]
    fn test_revocation_roundtrip() {
        let cacao = create_test_cacao();
        let revocation = TinyCloudRevocation::Cacao(cacao);
        
        let encoded = revocation.encode().expect("Failed to encode revocation");
        assert!(!encoded.contains('.'), "Cacao should not contain dots");
        
        let (decoded, bytes) = TinyCloudRevocation::decode(&encoded).expect("Failed to decode revocation");
        
        match decoded {
            TinyCloudRevocation::Cacao(_) => {}, // Expected
        }
        
        // For Cacao, bytes should be the decoded base64, not the original string
        assert_ne!(encoded.as_bytes(), bytes);
    }

    #[test]
    fn test_delegation_decode_format_detection() {
        // Test that strings with dots are decoded as Ucan
        let ucan = create_test_ucan();
        let ucan_string = ucan.encode().unwrap();
        let (decoded, _) = TinyCloudDelegation::decode(&ucan_string).unwrap();
        
        match decoded {
            TinyCloudDelegation::Ucan(_) => {}, // Expected
            TinyCloudDelegation::Cacao(_) => panic!("Expected Ucan for string with dots"),
        }
        
        // Test that strings without dots are decoded as Cacao
        let cacao = create_test_cacao();
        let cacao_delegation = TinyCloudDelegation::Cacao(Box::new(cacao));
        let cacao_string = cacao_delegation.encode().unwrap();
        let (decoded, _) = TinyCloudDelegation::decode(&cacao_string).unwrap();
        
        match decoded {
            TinyCloudDelegation::Cacao(_) => {}, // Expected  
            TinyCloudDelegation::Ucan(_) => panic!("Expected Cacao for string without dots"),
        }
    }

    #[test]
    fn test_invalid_base64_decode() {
        // Test invalid base64 for Cacao (no dots)
        let result = TinyCloudDelegation::decode("invalid-base64!");
        assert!(result.is_err());
        
        let result = TinyCloudRevocation::decode("invalid-base64!");
        assert!(result.is_err());
    }
}