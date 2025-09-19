declare module '@onebeyond/spdx-license-satisfies' {
  export function satisfiesAny(expression: string, licenses: string[]): boolean
  export function satisfiesAll(expression: string, licenses: string[]): boolean
}

declare module 'spdx-satisfies' {
  function satisfies(expression: string, range: string): boolean
  export = satisfies
}

declare module 'spdx-expression-parse' {
  function parse(expression: string): unknown
  export = parse
}
