// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// Records "a gov.br-authenticated CPF holder signed document hash H".
///
/// Takes the two proofs made by the backend:
///   signedDoc  (11 inputs): [h_hi, h_lo, sa_hi, sa_lo, key_hi, key_lo, cpf_hi, cpf_lo, ca_hi, ca_lo, signedDay]
///   cpfSigner  ( 6 inputs): [sa_hi, sa_lo, key_hi, key_lo, cpf_hi, cpf_lo]
/// and checks they describe the same signature (signedAttrs digest, leaf key, CPF commitment),
/// and that the certificate was issued by the trusted gov.br CA.
contract AttestationRegistry {
    struct Attestation {
        bytes32 signer; // salted CPF commitment: the on-chain pseudonym
        uint32 signedDay; // Unix day of the gov.br signature
        address submitter;
    }

    IHonkVerifier public immutable signedDocVerifier;
    IHonkVerifier public immutable cpfSignerVerifier;
    /// SHA-256 of the AC Final do Governo Federal do Brasil v1 RSA-4096 modulus.
    bytes32 public immutable trustedCa;

    /// docHash (SHA-256 of the PDF's signed byte ranges) → attestation.
    mapping(bytes32 => Attestation) public attestations;

    event Attested(bytes32 indexed docHash, bytes32 indexed signer, uint32 signedDay, address submitter);

    error InvalidProof(uint8 which);
    error ProofsNotLinked();
    error UntrustedCa();
    error AlreadyAttested();

    constructor(IHonkVerifier signedDoc, IHonkVerifier cpfSigner, bytes32 ca) {
        signedDocVerifier = signedDoc;
        cpfSignerVerifier = cpfSigner;
        trustedCa = ca;
    }

    function attest(
        bytes calldata docProof,
        bytes32[] calldata docInputs,
        bytes calldata signerProof,
        bytes32[] calldata signerInputs
    ) external returns (bytes32 docHash) {
        if (!signedDocVerifier.verify(docProof, docInputs)) revert InvalidProof(1);
        if (!cpfSignerVerifier.verify(signerProof, signerInputs)) revert InvalidProof(2);
        for (uint256 i = 0; i < 6; i++) {
            if (docInputs[2 + i] != signerInputs[i]) revert ProofsNotLinked();
        }
        if (join(docInputs[8], docInputs[9]) != trustedCa) revert UntrustedCa();

        docHash = join(docInputs[0], docInputs[1]);
        if (attestations[docHash].submitter != address(0)) revert AlreadyAttested();
        bytes32 signer = join(docInputs[6], docInputs[7]);
        uint32 day = uint32(uint256(docInputs[10]));
        attestations[docHash] = Attestation(signer, day, msg.sender);
        emit Attested(docHash, signer, day, msg.sender);
    }

    function join(bytes32 hi, bytes32 lo) internal pure returns (bytes32) {
        return bytes32((uint256(hi) << 128) | uint256(lo));
    }
}
