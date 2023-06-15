import React, { useEffect, useState } from "react";
// import "./App.css";
import { wrap } from "comlink";

import {
  Body,
  Container,
  Title,
  Link,
  LinkLogoContainer,
  LinkLogo,
  DivScrollable,
  Pre,
  Details,
  Summary,
  ZkDetails,
  DivLeftAlign,
  DetailButton,
  DivFlexInputContainer,
  DivFlexInput,
  DivFlexFormContainer,
  DivFlexForm,
  ZKDetailStatus,
  SafariWarning,
} from "./components";

import githubLogo from "./assets/images/GitHub-Mark-120px-plus.png";

function App() {
  const [zkStatus, setZkStatus] = useState("");
  const [threadPoolSize, setThreadPoolSize] = useState("1");
  const [proverInput, setProverInput] = useState("2");
  const [verifierInput, setVerifierInput] = useState("4");
  const [proof, setProof] = useState(null);

  useEffect(() => {
    setThreadPoolSize(navigator.hardwareConcurrency.toString());
  }, []);

  const showZkStatus = (inputStatus: string) => {
    setZkStatus(inputStatus);
  };

  const worker = new Worker(new URL("./halo-worker", import.meta.url), {
    name: "halo-worker",
    type: "module",
  });
  const workerApi = wrap<import("./halo-worker").HaloWorker>(worker);

  async function prove() {
    showZkStatus("Generating proof...");
    console.log("proverInput: " + proverInput);
    const start = performance.now();
    console.log("Starting prove()...");
    const proof = await workerApi.bls_signature_wasm(
      // BigInt(proverInput),
      parseInt(threadPoolSize)
    );
    // setProof(proof);
    const prove_finish = performance.now();
    const t_prove = prove_finish - start;
    console.log("Time to prove (s): ", t_prove / 1000);
    console.log("test.prove(): ", proof);
    showZkStatus(
      "Proof successfully generated. \nTime to prove (s): " +
        round(t_prove / 1000, 1)
    );
    return proof;
  }

  // async function verify() {
  //   showZkStatus("Verifying proof...");
  //   console.log("verifierInput: " + verifierInput);
  //   const start = performance.now();
  //   const verification = await workerApi.verify(
  //     BigInt(verifierInput),
  //     proof,
  //     parseInt(threadPoolSize)
  //   );
  //   const verify_finish = performance.now();
  //   const t_verify = verify_finish - start;
  //   console.log("Time to verify (s): ", t_verify / 1000);
  //   console.log("Verification: ", verification);
  //   showZkStatus(
  //     "Verification: " +
  //       String(verification) +
  //       ". \n" +
  //       "Time to verify (s): " +
  //       round(t_verify / 1000, 1)
  //   );
  // }

  async function handleButtonProve(event: React.ChangeEvent<HTMLInputElement>) {
    event.preventDefault();
    prove();
  }

  // async function handleButtonVerify(
  //   event: React.ChangeEvent<HTMLInputElement>
  // ) {
  //   event.preventDefault();
  //   verify();
  // }

  const handleProverInputChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    event.persist();
    const re = /^[0-9\b]+$/;
    if (event.target.value === "" || re.test(event.target.value)) {
      setProverInput(event.target.value);
    }
  };

  const handleVerifierInputChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    event.persist();
    const re = /^[0-9\b]+$/;
    if (event.target.value === "" || re.test(event.target.value)) {
      setVerifierInput(event.target.value);
    }
  };

  const handleThreadPoolSizeChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    event.persist();
    const re = /^[0-9\b]+$/;
    if (event.target.value === "" || re.test(event.target.value)) {
      setThreadPoolSize(event.target.value);
    }
  };

  return (
    <div className="App">
      <Container>
        <Body>
          <Title>halo2 Wasm Demo</Title>
          <DivLeftAlign>
            <Details>
              <Summary>Prove You Know The Square</Summary>
              <ZkDetails>
                <DivFlexInputContainer>
                  <label>
                    Thread Pool Size (Change to 4 if running on Apple M1. See{" "}
                    <a href="https://bugs.chromium.org/p/chromium/issues/detail?id=1228686&q=reporter%3Arreverser%40google.com&can=1">
                      here
                    </a>
                    ):
                  </label>
                  <DivFlexInput
                    type="number"
                    value={threadPoolSize}
                    onChange={handleThreadPoolSizeChange}
                  />
                </DivFlexInputContainer>
                <h2>Prover</h2>
                <DivFlexFormContainer>
                  <DivFlexForm onSubmit={handleButtonProve}>
                    <DivFlexInputContainer>
                      <label>Integer: </label>
                      <DivFlexInput
                        type="text"
                        value={proverInput}
                        onChange={handleProverInputChange}
                      />
                    </DivFlexInputContainer>
                    <DetailButton type="submit" value="Prove">
                      Prove
                    </DetailButton>
                  </DivFlexForm>
                </DivFlexFormContainer>
                <h2>Verifier</h2>
                <DivFlexInputContainer>
                  <label>Square: </label>
                  <DivFlexInput
                    type="text"
                    value={verifierInput}
                    onChange={handleVerifierInputChange}
                  />
                </DivFlexInputContainer>
                <h3>Proof</h3>
                {proof != null && (
                  <DivScrollable>
                    <Pre>{JSON.stringify(proof, null, 2)}</Pre>
                  </DivScrollable>
                )}
                {/* <DetailButton onClick={handleButtonVerify}>Verify</DetailButton> */}
                <ZKDetailStatus>{zkStatus}</ZKDetailStatus>
                <SafariWarning>
                  Note: As stated in the{" "}
                  <a href="https://zcash.github.io/halo2/user/wasm-port.html#safari">
                    halo2 Book
                  </a>
                  , Safari is not currently supported.
                </SafariWarning>
              </ZkDetails>
            </Details>
          </DivLeftAlign>
          <LinkLogoContainer>
            <Link href="https://github.com/flyingnobita/halo2-wasm-demo">
              <LinkLogo src={githubLogo} alt="github" />
            </Link>
          </LinkLogoContainer>
        </Body>
      </Container>
    </div>
  );
}

function round(value: number, precision: number) {
  var multiplier = Math.pow(10, precision || 0);
  return Math.round(value * multiplier) / multiplier;
}

export default App;
