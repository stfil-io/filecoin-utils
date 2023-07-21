import BN from 'bn.js'

import { Address } from '../address'
import { serializeBigNum } from './utils'
import { encode, decode } from '@ipld/dag-cbor'
import { TransactionJSON, TxInputData, TxVersion } from '../artifacts/transaction'
import { NetworkPrefix } from '../artifacts/address'
import { Buffer } from 'buffer'

/**
 * Represents a transaction in the filecoin blockchain.
 */
export class Transaction {
  constructor(
    public version: TxVersion,
    public to: Address,
    public from: Address,
    public nonce: number,
    public value: string,
    public gasLimit: number,
    public gasFeeCap: string,
    public gasPremium: string,
    public method: number,
    public params: string
  ) {
    if (value === '' || value.includes('-')) throw new Error('value must not be empty or negative')
  }

  /**
   * Create a new Transaction instance from a cbor encoded transaction
   * @param networkPrefix - network type this tx comes from
   * @param cborMessage - cbor encoded tx to parse
   * @returns a new Transaction instance
   */
  static fromCBOR = async (networkPrefix: NetworkPrefix, cborMessage: Buffer | string): Promise<Transaction> => {
    if (typeof cborMessage === 'string') cborMessage = Buffer.from(cborMessage, 'hex')

    const decoded = decode<TxInputData>(cborMessage)
    if (!(decoded instanceof Array)) throw new Error('Decoded raw tx should be an array')
    if (decoded.length < 10) throw new Error('The cbor is missing some fields... please verify you have 9 fields.')

    const [txVersion, toRaw, fromRaw, nonceRaw, valueRaw, gasLimitRaw, gasFeeCapRaw, gasPremiumRaw, methodRaw, paramsRaw] = decoded
    if (txVersion !== TxVersion.Zero) throw new Error('Unsupported version')
    if (valueRaw[0] === 0x01) throw new Error('Value cant be negative')

    const value = new BN(Buffer.from(valueRaw).toString('hex'), 16).toString(10)
    const gasFeeCap = new BN(Buffer.from(gasFeeCapRaw).toString('hex'), 16).toString(10)
    const gasPremium = new BN(Buffer.from(gasPremiumRaw).toString('hex'), 16).toString(10)

    return new Transaction(
      txVersion,
      Address.fromBytes(networkPrefix, toRaw),
      Address.fromBytes(networkPrefix, fromRaw),
      nonceRaw,
      value,
      gasLimitRaw,
      gasFeeCap,
      gasPremium,
      methodRaw,
      paramsRaw.toString('base64')
    )
  }

  /**
   * Create a new Transaction instance from a json object
   * @param message - raw json object containing transaction fields in json types
   * @returns a new Transaction instance
   */
  static fromJSON = (message: unknown): Transaction => {
    if (typeof message !== 'object' || message == null) throw new Error('tx should be an json object')

    if (!('To' in message) || typeof message['To'] !== 'string') throw new Error("'To' is a required field and has to be a 'string'")

    if (!('From' in message) || typeof message['From'] !== 'string') throw new Error("'From' is a required field and has to be a 'string'")

    if (!('Nonce' in message) || typeof message['Nonce'] !== 'number') throw new Error("'Nonce' is a required field and has to be a 'number'")

    if (!('Value' in message) || typeof message['Value'] !== 'string' || message['Value'] === '' || message['Value'].includes('-'))
      throw new Error("'Value' is a required field and has to be a 'string' but not empty or negative")

    if (!('GasFeeCap' in message) || typeof message['GasFeeCap'] !== 'string') throw new Error("'GasFeeCap' is a required field and has to be a 'string'")

    if (!('GasPremium' in message) || typeof message['GasPremium'] !== 'string') throw new Error("'GasPremium' is a required field and has to be a 'string'")

    if (!('GasLimit' in message) || typeof message['GasLimit'] !== 'number') throw new Error("'GasLimit' is a required field and has to be a 'number'")

    if (!('Method' in message) || typeof message['Method'] !== 'number') throw new Error("'Method' is a required field and has to be a 'number'")

    if (!('Params' in message) || typeof message['Params'] !== 'string') throw new Error("'Params' is a required field and has to be a 'string'")

    return new Transaction(
      TxVersion.Zero,
      Address.fromString(message.To),
      Address.fromString(message.From),
      message.Nonce,
      message.Value,
      message.GasLimit,
      message.GasFeeCap,
      message.GasPremium,
      message.Method,
      message.Params
    )
  }

  /**
   * Export the current transaction fields to a JSON object (that can be saved in a file, or transmitted to anywhere)
   * @returns a JSON object representing the current transaction
   */
  toJSON = (): TransactionJSON => ({
    To: this.to.toString(),
    From: this.from.toString(),
    Nonce: this.nonce,
    Value: this.value,
    Params: this.params,
    GasFeeCap: this.gasFeeCap,
    GasPremium: this.gasPremium,
    GasLimit: this.gasLimit,
    Method: this.method,
  })

  /**
   * Encode the current transaction as CBOR following filecoin specifications. This is the format required as input to sign it.
   * @returns a cbor encoded transaction (as buffer)
   */
  serialize = async (): Promise<Buffer> => {
    const message_to_encode: TxInputData = [
      this.version,
      this.to.toBytes(),
      this.from.toBytes(),
      this.nonce,
      serializeBigNum(this.value, 10),
      this.gasLimit,
      serializeBigNum(this.gasFeeCap, 10),
      serializeBigNum(this.gasPremium, 10),
      this.method,
      Buffer.from(this.params, 'base64'),
    ]

    return Buffer.from(encode(message_to_encode))
  }
}
