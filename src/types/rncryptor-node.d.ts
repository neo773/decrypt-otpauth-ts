declare module 'rncryptor-node' {
  interface RNCryptor {
    Decrypt(b64str: string, password: string): Buffer | undefined;
  }

  const rncryptor: RNCryptor;
  export default rncryptor;
} 