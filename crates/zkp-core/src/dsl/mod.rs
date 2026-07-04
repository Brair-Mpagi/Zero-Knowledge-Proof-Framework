//! # Circuit DSL
//!
//! A simple declarative language for describing arithmetic circuits.
//! Compiles to CircuitBuilder calls.

pub mod stdlib;

use crate::field::FieldElement;
use crate::circuit::{CircuitBuilder, Variable, LinearCombination};
use serde::{Serialize, Deserialize};

/// A parsed DSL program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DslProgram {
    pub name: String,
    pub statements: Vec<DslStatement>,
}

/// A DSL statement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DslStatement {
    /// Declare a public input: `public x`
    PublicInput(String),
    /// Declare a private input: `private x`
    PrivateInput(String),
    /// Multiplication constraint: `mul a b c` (a * b = c)
    Mul(String, String, String),
    /// Addition constraint: `add a b c` (a + b = c)
    Add(String, String, String),
    /// Equality assertion: `assert_eq a b`
    AssertEq(String, String),
    /// Boolean assertion: `assert_bool a`
    AssertBool(String),
    /// Nonzero assertion: `assert_nonzero a`
    AssertNonzero(String),
    /// Constant assertion: `assert_const a 42`
    AssertConst(String, u64),
    /// Different assertion: `assert_diff a b`
    AssertDiff(String, String),
}

/// Parse a DSL source string into a program.
pub fn parse(source: &str) -> Result<DslProgram, String> {
    let mut name = "unnamed".to_string();
    let mut statements = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() { continue; }

        match tokens[0] {
            "circuit" => {
                if tokens.len() < 2 {
                    return Err(format!("Line {}: 'circuit' requires a name", line_num + 1));
                }
                name = tokens[1].to_string();
            }
            "public" => {
                if tokens.len() < 2 {
                    return Err(format!("Line {}: 'public' requires a variable name", line_num + 1));
                }
                statements.push(DslStatement::PublicInput(tokens[1].to_string()));
            }
            "private" => {
                if tokens.len() < 2 {
                    return Err(format!("Line {}: 'private' requires a variable name", line_num + 1));
                }
                statements.push(DslStatement::PrivateInput(tokens[1].to_string()));
            }
            "mul" => {
                if tokens.len() < 4 {
                    return Err(format!("Line {}: 'mul' requires 3 args: a b c", line_num + 1));
                }
                statements.push(DslStatement::Mul(
                    tokens[1].to_string(), tokens[2].to_string(), tokens[3].to_string(),
                ));
            }
            "add" => {
                if tokens.len() < 4 {
                    return Err(format!("Line {}: 'add' requires 3 args: a b c", line_num + 1));
                }
                statements.push(DslStatement::Add(
                    tokens[1].to_string(), tokens[2].to_string(), tokens[3].to_string(),
                ));
            }
            "assert_eq" => {
                if tokens.len() < 3 {
                    return Err(format!("Line {}: 'assert_eq' requires 2 args", line_num + 1));
                }
                statements.push(DslStatement::AssertEq(tokens[1].to_string(), tokens[2].to_string()));
            }
            "assert_bool" => {
                if tokens.len() < 2 {
                    return Err(format!("Line {}: 'assert_bool' requires 1 arg", line_num + 1));
                }
                statements.push(DslStatement::AssertBool(tokens[1].to_string()));
            }
            "assert_nonzero" => {
                if tokens.len() < 2 {
                    return Err(format!("Line {}: 'assert_nonzero' requires 1 arg", line_num + 1));
                }
                statements.push(DslStatement::AssertNonzero(tokens[1].to_string()));
            }
            "assert_const" => {
                if tokens.len() < 3 {
                    return Err(format!("Line {}: 'assert_const' requires 2 args", line_num + 1));
                }
                let val: u64 = tokens[2].parse()
                    .map_err(|_| format!("Line {}: invalid constant '{}'", line_num + 1, tokens[2]))?;
                statements.push(DslStatement::AssertConst(tokens[1].to_string(), val));
            }
            "assert_diff" => {
                if tokens.len() < 3 {
                    return Err(format!("Line {}: 'assert_diff' requires 2 args", line_num + 1));
                }
                statements.push(DslStatement::AssertDiff(tokens[1].to_string(), tokens[2].to_string()));
            }
            _ => {
                return Err(format!("Line {}: unknown keyword '{}'", line_num + 1, tokens[0]));
            }
        }
    }

    Ok(DslProgram { name, statements })
}

/// Compile a DSL program into a CircuitBuilder.
pub fn compile(program: &DslProgram) -> Result<CircuitBuilder, String> {
    use std::collections::HashMap;

    let mut builder = CircuitBuilder::new();
    let mut vars: HashMap<String, Variable> = HashMap::new();

    for stmt in &program.statements {
        match stmt {
            DslStatement::PublicInput(name) => {
                let var = builder.alloc_public_input_named(name);
                vars.insert(name.clone(), var);
            }
            DslStatement::PrivateInput(name) => {
                let var = builder.alloc_private_input_named(name);
                vars.insert(name.clone(), var);
            }
            DslStatement::Mul(a, b, c) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                let vb = *vars.get(b).ok_or(format!("Undefined variable '{}'", b))?;
                // Auto-allocate output if not declared
                let vc = if let Some(v) = vars.get(c) {
                    *v
                } else {
                    let v = builder.alloc_internal_named(c);
                    vars.insert(c.clone(), v);
                    v
                };
                builder.mul(va, vb, vc);
            }
            DslStatement::Add(a, b, c) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                let vb = *vars.get(b).ok_or(format!("Undefined variable '{}'", b))?;
                let vc = if let Some(v) = vars.get(c) {
                    *v
                } else {
                    let v = builder.alloc_internal_named(c);
                    vars.insert(c.clone(), v);
                    v
                };
                builder.add(va, vb, vc);
            }
            DslStatement::AssertEq(a, b) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                let vb = *vars.get(b).ok_or(format!("Undefined variable '{}'", b))?;
                builder.assert_equal(va, vb);
            }
            DslStatement::AssertBool(a) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                builder.assert_bool(va);
            }
            DslStatement::AssertNonzero(a) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                builder.assert_nonzero(va);
            }
            DslStatement::AssertConst(a, val) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                builder.assert_constant(va, FieldElement::from_u64(*val));
            }
            DslStatement::AssertDiff(a, b) => {
                let va = *vars.get(a).ok_or(format!("Undefined variable '{}'", a))?;
                let vb = *vars.get(b).ok_or(format!("Undefined variable '{}'", b))?;
                builder.assert_different(va, vb);
            }
        }
    }

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let src = r#"
            circuit square_root
            private x
            public y
            mul x x y
        "#;
        let prog = parse(src).unwrap();
        assert_eq!(prog.name, "square_root");
        assert_eq!(prog.statements.len(), 3);
    }

    #[test]
    fn test_compile_and_build() {
        let src = r#"
            circuit test
            private x
            public y
            mul x x y
        "#;
        let prog = parse(src).unwrap();
        let builder = compile(&prog).unwrap();
        let r1cs = builder.build();
        assert_eq!(r1cs.num_constraints(), 1);
    }

    #[test]
    fn test_parse_comments() {
        let src = r#"
            # This is a comment
            circuit test
            // Another comment
            private x
            public y
            mul x x y
        "#;
        let prog = parse(src).unwrap();
        assert_eq!(prog.name, "test");
    }

    #[test]
    fn test_parse_error() {
        let src = "unknown_keyword foo";
        assert!(parse(src).is_err());
    }
}
