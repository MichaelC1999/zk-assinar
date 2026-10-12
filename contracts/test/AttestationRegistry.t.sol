// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AttestationRegistry, IHonkVerifier} from "../src/AttestationRegistry.sol";

/// Uses the real proofs of the sample PDF written by the backend to work/out
/// (run scripts/test.py, or `zk-assinar prove ... --out work/out`).
contract AttestationRegistryTest is Test {
    bytes32 constant AC_FINAL_V1 = 0x99c1ee8121174e6eaa19a3bfd411066f1680516c812376db564baf96bc51b68d;

    AttestationRegistry reg;
    bytes docProof;
    bytes32[] docIn;
    bytes signerProof;
    bytes32[] signerIn;

    function setUp() public {
        IHonkVerifier d = IHonkVerifier(deployCode("SignedDocVerifier.sol:SignedDocVerifier"));
        IHonkVerifier s = IHonkVerifier(deployCode("CpfSignerVerifier.sol:CpfSignerVerifier"));
        reg = new AttestationRegistry(d, s, AC_FINAL_V1);
        (docProof, docIn) = load("signed_doc", 11);
        (signerProof, signerIn) = load("cpf_signer", 6);
    }

    function load(string memory name, uint256 n) internal view returns (bytes memory proof, bytes32[] memory w) {
        string memory dir = string.concat(vm.projectRoot(), "/../work/out/", name);
        proof = vm.readFileBinary(string.concat(dir, "/proof"));
        bytes memory pi = vm.readFileBinary(string.concat(dir, "/public_inputs"));
        w = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 x;
            assembly ("memory-safe") { x := mload(add(add(pi, 32), mul(i, 32))) }
            w[i] = x;
        }
    }

    function test_attest() public {
        uint256 g = gasleft();
        bytes32 docHash = reg.attest(docProof, docIn, signerProof, signerIn);
        emit log_named_uint("attest gas", g - gasleft());
        (bytes32 signer, uint32 day, address by) = reg.attestations(docHash);
        assertEq(docHash, bytes32((uint256(docIn[0]) << 128) | uint256(docIn[1])));
        assertEq(signer, bytes32((uint256(docIn[6]) << 128) | uint256(docIn[7])));
        assertEq(day, uint32(uint256(docIn[10])));
        assertEq(by, address(this));
    }

    function test_replay_rejected() public {
        reg.attest(docProof, docIn, signerProof, signerIn);
        vm.expectRevert(AttestationRegistry.AlreadyAttested.selector);
        reg.attest(docProof, docIn, signerProof, signerIn);
    }

    function test_tampered_input_rejected() public {
        docIn[6] = bytes32(uint256(docIn[6]) ^ 1); // claim a different CPF commitment
        vm.expectRevert();
        reg.attest(docProof, docIn, signerProof, signerIn);
    }

    function test_untrusted_ca_rejected() public {
        AttestationRegistry other = new AttestationRegistry(
            reg.signedDocVerifier(), reg.cpfSignerVerifier(), bytes32(uint256(1))
        );
        vm.expectRevert(AttestationRegistry.UntrustedCa.selector);
        other.attest(docProof, docIn, signerProof, signerIn);
    }
}
