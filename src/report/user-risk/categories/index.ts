import type { UserRiskCategoryEvaluator } from '../types.js';
import {
  accesoGeneralNavegadorStaticRules,
  evaluateAccesoGeneralNavegador,
} from './acceso-general-navegador.js';
import {
  accesoHistorialStaticRules,
  evaluateAccesoHistorial,
} from './acceso-historial.js';
import {
  capturaCredencialesStaticRules,
  evaluateCapturaCredenciales,
} from './captura-credenciales.js';
import {
  descargasArchivosStaticRules,
  evaluateDescargasArchivos,
} from './descargas-archivos.js';
import { evaluateKeylogging, keyloggingStaticRules } from './keylogging.js';
import {
  evaluateLecturaInformacion,
  lecturaInformacionStaticRules,
} from './lectura-informacion.js';
import {
  evaluateManipulacionTrafico,
  manipulacionTraficoStaticRules,
} from './manipulacion-trafico.js';
import {
  evaluateModificacionPaginas,
  modificacionPaginasStaticRules,
} from './modificacion-paginas.js';
import {
  evaluateOfuscacionTransparencia,
  ofuscacionTransparenciaStaticRules,
} from './ofuscacion-transparencia.js';
import {
  evaluateSeguimientoPrivacidad,
  seguimientoPrivacidadStaticRules,
} from './seguimiento-privacidad.js';

export const USER_RISK_CATEGORY_EVALUATORS: UserRiskCategoryEvaluator[] = [
  evaluateAccesoGeneralNavegador,
  evaluateModificacionPaginas,
  evaluateLecturaInformacion,
  evaluateCapturaCredenciales,
  evaluateKeylogging,
  evaluateSeguimientoPrivacidad,
  evaluateManipulacionTrafico,
  evaluateAccesoHistorial,
  evaluateDescargasArchivos,
  evaluateOfuscacionTransparencia,
];

export const USER_RISK_STATIC_RULES = [
  ...accesoGeneralNavegadorStaticRules,
  ...modificacionPaginasStaticRules,
  ...lecturaInformacionStaticRules,
  ...capturaCredencialesStaticRules,
  ...keyloggingStaticRules,
  ...seguimientoPrivacidadStaticRules,
  ...manipulacionTraficoStaticRules,
  ...accesoHistorialStaticRules,
  ...descargasArchivosStaticRules,
  ...ofuscacionTransparenciaStaticRules,
];
