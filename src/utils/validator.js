// src/utils/validator.js - Middleware de validare a datelor pentru API-uri
// Oferă validare robustă pentru toate endpoint-urile API

/**
 * Validator - Sistem de validare a datelor pentru API-uri
 * 
 * Funcționalități:
 * - Validare de tip și format pentru toate datele de intrare
 * - Sanitizare pentru prevenirea injecțiilor
 * - Suport pentru validări personalizate
 * - Gestionarea erorilor consistentă
 */

// Tipuri de validare suportate
const TYPES = {
  STRING: 'string',
  NUMBER: 'number',
  BOOLEAN: 'boolean',
  OBJECT: 'object',
  ARRAY: 'array',
  EMAIL: 'email',
  DATE: 'date',
  UUID: 'uuid',
  URL: 'url',
  ENUM: 'enum'
};

// Regex-uri pentru validări comune
const PATTERNS = {
  EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  URL: /^(https?):\/\/[^\s$.?#].[^\s]*$/i,
  SAFE_STRING: /^[^<>'"`;=]*$/
};

/**
 * Validează o valoare conform unui schema specificat
 * @param {any} value - Valoarea de validat
 * @param {Object} schema - Schema de validare
 * @returns {Object} Rezultatul validării {valid, value, errors}
 */
function validate(value, schema) {
  const result = {
    valid: true,
    value: value,
    errors: []
  };

  // Verifică dacă valoarea este obligatorie
  if (schema.required && (value === undefined || value === null || value === '')) {
    result.valid = false;
    result.errors.push(`Câmpul este obligatoriu`);
    return result;
  }

  // Dacă valoarea nu este definită și nu este obligatorie, returnăm valid
  if (value === undefined || value === null) {
    return result;
  }

  // Validare în funcție de tip
  switch (schema.type) {
    case TYPES.STRING:
      if (typeof value !== 'string') {
        result.valid = false;
        result.errors.push(`Valoarea trebuie să fie un text`);
      } else {
        // Validare lungime minimă
        if (schema.minLength !== undefined && value.length < schema.minLength) {
          result.valid = false;
          result.errors.push(`Textul trebuie să aibă minim ${schema.minLength} caractere`);
        }
        
        // Validare lungime maximă
        if (schema.maxLength !== undefined && value.length > schema.maxLength) {
          result.valid = false;
          result.errors.push(`Textul trebuie să aibă maxim ${schema.maxLength} caractere`);
        }
        
        // Validare pattern
        if (schema.pattern && !schema.pattern.test(value)) {
          result.valid = false;
          result.errors.push(`Formatul textului este invalid`);
        }
        
        // Sanitizare
        if (schema.sanitize) {
          result.value = sanitizeString(value);
        }
      }
      break;
      
    case TYPES.NUMBER:
      const num = Number(value);
      if (isNaN(num)) {
        result.valid = false;
        result.errors.push(`Valoarea trebuie să fie un număr`);
      } else {
        result.value = num;
        
        // Validare minim
        if (schema.min !== undefined && num < schema.min) {
          result.valid = false;
          result.errors.push(`Numărul trebuie să fie minim ${schema.min}`);
        }
        
        // Validare maxim
        if (schema.max !== undefined && num > schema.max) {
          result.valid = false;
          result.errors.push(`Numărul trebuie să fie maxim ${schema.max}`);
        }
        
        // Validare număr întreg
        if (schema.integer && !Number.isInteger(num)) {
          result.valid = false;
          result.errors.push(`Numărul trebuie să fie întreg`);
        }
      }
      break;
      
    case TYPES.BOOLEAN:
      if (typeof value === 'boolean') {
        result.value = value;
      } else if (value === 'true' || value === '1' || value === 1) {
        result.value = true;
      } else if (value === 'false' || value === '0' || value === 0) {
        result.value = false;
      } else {
        result.valid = false;
        result.errors.push(`Valoarea trebuie să fie boolean (true/false)`);
      }
      break;
      
    case TYPES.EMAIL:
      if (typeof value !== 'string' || !PATTERNS.EMAIL.test(value)) {
        result.valid = false;
        result.errors.push(`Adresa de email este invalidă`);
      }
      break;
      
    case TYPES.DATE:
      const date = new Date(value);
      if (isNaN(date.getTime())) {
        result.valid = false;
        result.errors.push(`Data este invalidă`);
      } else {
        result.value = date;
        
        // Validare dată minimă
        if (schema.minDate && date < new Date(schema.minDate)) {
          result.valid = false;
          result.errors.push(`Data trebuie să fie după ${new Date(schema.minDate).toLocaleDateString()}`);
        }
        
        // Validare dată maximă
        if (schema.maxDate && date > new Date(schema.maxDate)) {
          result.valid = false;
          result.errors.push(`Data trebuie să fie înainte de ${new Date(schema.maxDate).toLocaleDateString()}`);
        }
      }
      break;
      
    case TYPES.ARRAY:
      if (!Array.isArray(value)) {
        result.valid = false;
        result.errors.push(`Valoarea trebuie să fie un array`);
      } else {
        // Validare lungime minimă
        if (schema.minItems !== undefined && value.length < schema.minItems) {
          result.valid = false;
          result.errors.push(`Array-ul trebuie să aibă minim ${schema.minItems} elemente`);
        }
        
        // Validare lungime maximă
        if (schema.maxItems !== undefined && value.length > schema.maxItems) {
          result.valid = false;
          result.errors.push(`Array-ul trebuie să aibă maxim ${schema.maxItems} elemente`);
        }
        
        // Validare elemente
        if (schema.items && result.valid) {
          const validatedItems = [];
          for (let i = 0; i < value.length; i++) {
            const itemResult = validate(value[i], schema.items);
            if (!itemResult.valid) {
              result.valid = false;
              result.errors.push(`Elementul ${i}: ${itemResult.errors.join(', ')}`);
            }
            validatedItems.push(itemResult.value);
          }
          result.value = validatedItems;
        }
      }
      break;
      
    case TYPES.OBJECT:
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        result.valid = false;
        result.errors.push(`Valoarea trebuie să fie un obiect`);
      } else if (schema.properties) {
        const validatedObj = {};
        
        // Validare proprietăți obligatorii
        if (schema.required) {
          for (const requiredProp of schema.required) {
            if (!(requiredProp in value)) {
              result.valid = false;
              result.errors.push(`Proprietatea "${requiredProp}" este obligatorie`);
            }
          }
        }
        
        // Validare proprietăți
        for (const [propName, propSchema] of Object.entries(schema.properties)) {
          if (propName in value) {
            const propResult = validate(value[propName], propSchema);
            if (!propResult.valid) {
              result.valid = false;
              result.errors.push(`Proprietatea "${propName}": ${propResult.errors.join(', ')}`);
            }
            validatedObj[propName] = propResult.value;
          } else if (propSchema.default !== undefined) {
            validatedObj[propName] = propSchema.default;
          }
        }
        
        // Proprietăți adiționale
        if (schema.additionalProperties === false) {
          for (const propName in value) {
            if (!(propName in schema.properties)) {
              result.valid = false;
              result.errors.push(`Proprietatea "${propName}" nu este permisă`);
            }
          }
        } else {
          for (const propName in value) {
            if (!(propName in schema.properties)) {
              validatedObj[propName] = value[propName];
            }
          }
        }
        
        result.value = validatedObj;
      }
      break;
      
    case TYPES.ENUM:
      if (!schema.values || !Array.isArray(schema.values) || !schema.values.includes(value)) {
        result.valid = false;
        result.errors.push(`Valoarea trebuie să fie una dintre: ${schema.values.join(', ')}`);
      }
      break;
      
    case TYPES.UUID:
      if (typeof value !== 'string' || !PATTERNS.UUID.test(value)) {
        result.valid = false;
        result.errors.push(`UUID invalid`);
      }
      break;
      
    case TYPES.URL:
      if (typeof value !== 'string' || !PATTERNS.URL.test(value)) {
        result.valid = false;
        result.errors.push(`URL invalid`);
      }
      break;
      
    default:
      if (typeof value !== schema.type) {
        result.valid = false;
        result.errors.push(`Tipul valorii este invalid, se așteaptă ${schema.type}`);
      }
  }
  
  // Validare personalizată
  if (schema.validate && typeof schema.validate === 'function' && result.valid) {
    try {
      const customResult = schema.validate(result.value);
      if (customResult !== true) {
        result.valid = false;
        result.errors.push(customResult || 'Validare personalizată eșuată');
      }
    } catch (err) {
      result.valid = false;
      result.errors.push(`Eroare la validare: ${err.message}`);
    }
  }
  
  return result;
}

/**
 * Sanitizează un string pentru a preveni injecții
 * @param {string} str - String-ul de sanitizat
 * @returns {string} String-ul sanitizat
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return str;
  
  // Înlocuiește caracterele potențial periculoase
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;')
    .replace(/\$/g, '&#36;');
}

/**
 * Middleware Fastify pentru validarea datelor de intrare
 * @param {Object} schema - Schema de validare
 * @returns {Function} Middleware Fastify
 */
function validateRequest(schema) {
  return function(req, reply, done) {
    const errors = {};
    let hasErrors = false;
    
    // Validare parametri
    if (schema.params) {
      const result = validate(req.params, {
        type: TYPES.OBJECT,
        properties: schema.params
      });
      
      if (!result.valid) {
        hasErrors = true;
        errors.params = result.errors;
      } else {
        req.params = result.value;
      }
    }
    
    // Validare query
    if (schema.query) {
      const result = validate(req.query, {
        type: TYPES.OBJECT,
        properties: schema.query
      });
      
      if (!result.valid) {
        hasErrors = true;
        errors.query = result.errors;
      } else {
        req.query = result.value;
      }
    }
    
    // Validare body
    if (schema.body) {
      const result = validate(req.body, schema.body);
      
      if (!result.valid) {
        hasErrors = true;
        errors.body = result.errors;
      } else {
        req.body = result.value;
      }
    }
    
    // Validare headers
    if (schema.headers) {
      const result = validate(req.headers, {
        type: TYPES.OBJECT,
        properties: schema.headers
      });
      
      if (!result.valid) {
        hasErrors = true;
        errors.headers = result.errors;
      }
    }
    
    if (hasErrors) {
      reply.code(400).send({
        error: 'Validation Error',
        details: errors
      });
      return;
    }
    
    done();
  };
}

// Exportă funcțiile și constantele
export default {
  validate,
  validateRequest,
  sanitizeString,
  TYPES,
  PATTERNS
};