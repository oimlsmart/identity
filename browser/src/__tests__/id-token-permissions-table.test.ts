// ─────────────────────────────────────────────────────────────────────
// The Cloudflare-style permissions picker's table mappers (dash-
// cloudflare.html's Permission Editor shape): per GROUP a table whose
// rows are the RESOURCES (name + description) and whose columns are
// the VERBS the group actually declares (checkbox cells) — plus the
// row's leading "All" cell (the resource stem) and the group header's
// whole-service stem, preserving TODO.openapi/19's hierarchy on top of
// the reference's layout.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import {
  groupTable,
  type CatalogGroup,
} from '../components/token-permissions'

const GROUP: CatalogGroup = {
  id: 'portal',
  description: 'the console',
  permissions: [
    { id: 'portal.models.read', description: 'Reads the model library.' },
    { id: 'portal.models.edit', description: 'Maintains the model library.' },
    { id: 'portal.claims.edit', description: 'Files the claims.' },
  ],
}

describe('groupTable — the Cloudflare-editor projection', () => {
  it('rows are the resources; the columns are the verbs the group declares, read/edit first', () => {
    const table = groupTable(GROUP)
    expect(table.columns).toEqual(['read', 'edit'])
    expect(table.rows.map(r => r.resource)).toEqual(['portal.claims', 'portal.models'])
  })

  it('a row carries the description (the read verb blurb, else the first verb\'s) and its cells map verb → full id', () => {
    const table = groupTable(GROUP)
    const models = table.rows.find(r => r.resource === 'portal.models')!
    expect(models.description).toBe('Reads the model library.')
    expect(models.cells).toEqual({ read: 'portal.models.read', edit: 'portal.models.edit' })
    const claims = table.rows.find(r => r.resource === 'portal.claims')!
    expect(claims.description).toBe('Files the claims.')
    expect(claims.cells).toEqual({ edit: 'portal.claims.edit' })
  })

  it('a verb beyond read/edit takes its own column (federation\'s send/revoke/…), alphabetical after the pair', () => {
    const fed: CatalogGroup = {
      id: 'federation', description: 'the exchange',
      permissions: [
        { id: 'federation.peers.read', description: 'r' },
        { id: 'federation.peers.revoke', description: 'x' },
        { id: 'federation.dispatch.send', description: 's' },
      ],
    }
    const table = groupTable(fed)
    expect(table.columns).toEqual(['read', 'revoke', 'send'])
    const peers = table.rows.find(r => r.resource === 'federation.peers')!
    expect(peers.cells).toEqual({ read: 'federation.peers.read', revoke: 'federation.peers.revoke' })
  })

  it('an empty group answers an empty table', () => {
    expect(groupTable({ id: 'cnml', description: '', permissions: [] })).toEqual({ columns: [], rows: [] })
  })
})
