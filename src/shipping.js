'use strict';

/**
 * Calculadora de frete por estado brasileiro.
 *
 * Lógica:
 *  - Frete GRÁTIS se subtotal >= FREE_SHIPPING_THRESHOLD
 *  - Caso contrário, valor baseado na zona geográfica do estado destino
 *  - Estado de origem: São Paulo (SP)
 */

const FREE_SHIPPING_THRESHOLD = parseFloat(process.env.FREE_SHIPPING_THRESHOLD) || 100;

// ─── Zonas de frete ────────────────────────────────────────────────────────────
// Valores em R$ — ajuste conforme sua tabela real de transportadora
const SHIPPING_ZONES = {
  // Zona 1 — São Paulo capital e interior próximo (mais barato, próximo da origem)
  Z1: { label: 'São Paulo (capital e região)', price: 9.90,  days: '1–2' },
  // Zona 2 — Sul + Rio de Janeiro + Minas Gerais + Espírito Santo
  Z2: { label: 'Sul e Sudeste',                price: 14.90, days: '2–4' },
  // Zona 3 — Centro-Oeste + demais do Nordeste
  Z3: { label: 'Centro-Oeste e Norte-Nordeste', price: 22.90, days: '4–7' },
  // Zona 4 — Norte + extremo Nordeste (mais caro, maior distância)
  Z4: { label: 'Norte e extremo Nordeste',      price: 28.90, days: '5–8' },
};

// Mapeamento estado → zona
const STATE_ZONE = {
  // Zona 1 – São Paulo
  SP: 'Z1',

  // Zona 2 – Sul + Sudeste (exceto SP)
  RJ: 'Z2', MG: 'Z2', ES: 'Z2',
  PR: 'Z2', SC: 'Z2', RS: 'Z2',

  // Zona 3 – Centro-Oeste + parte do Nordeste
  MS: 'Z3', MT: 'Z3', GO: 'Z3', DF: 'Z3',
  BA: 'Z3', SE: 'Z3', AL: 'Z3', PE: 'Z3', PB: 'Z3',

  // Zona 4 – Norte + extremo Nordeste
  AM: 'Z4', PA: 'Z4', RO: 'Z4', AC: 'Z4', RR: 'Z4', AP: 'Z4', TO: 'Z4',
  MA: 'Z4', PI: 'Z4', CE: 'Z4', RN: 'Z4',
};

/**
 * Calcula o frete dado o estado de destino e o subtotal do pedido.
 *
 * @param {string} state   Sigla do estado (ex: 'SP', 'RN')
 * @param {number} subtotal Valor dos produtos (sem frete)
 * @returns {{ cost: number, free: boolean, zone: string, label: string, days: string }}
 */
function calculateShipping(state, subtotal) {
  const uf    = (state || '').toUpperCase().trim();
  const isFree = subtotal >= FREE_SHIPPING_THRESHOLD;

  if (isFree) {
    return {
      cost:  0,
      free:  true,
      zone:  STATE_ZONE[uf] || 'Z3',
      label: SHIPPING_ZONES[STATE_ZONE[uf] || 'Z3'].label,
      days:  SHIPPING_ZONES[STATE_ZONE[uf] || 'Z3'].days,
      threshold: FREE_SHIPPING_THRESHOLD,
    };
  }

  const zoneKey = STATE_ZONE[uf] || 'Z3'; // padrão Z3 para estados não mapeados
  const zone    = SHIPPING_ZONES[zoneKey];

  return {
    cost:      zone.price,
    free:      false,
    zone:      zoneKey,
    label:     zone.label,
    days:      zone.days,
    threshold: FREE_SHIPPING_THRESHOLD,
  };
}

/**
 * Retorna a tabela completa de zonas (para exibição no frontend).
 */
function getShippingTable() {
  return {
    zones: SHIPPING_ZONES,
    stateZone: STATE_ZONE,
    freeThreshold: FREE_SHIPPING_THRESHOLD,
  };
}

module.exports = { calculateShipping, getShippingTable, FREE_SHIPPING_THRESHOLD };
