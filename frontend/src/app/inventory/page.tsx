'use client'

import { useEffect, useState } from 'react'
import { certificateApi, Certificate } from '@/lib/api'
import { formatDate, getDaysUntilExpiry, getExpiryStatus, downloadBase64File } from '@/lib/utils'
import { Shield, AlertTriangle, CheckCircle, Clock, Search, Filter, Download, RotateCcw, X, Copy, RefreshCw, Upload } from 'lucide-react'
import { toast } from 'react-hot-toast'
import Link from 'next/link'
import { useAuth } from '@/lib/auth-context'

export default function Inventory() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null)
  const [sourceFilter, setSourceFilter] = useState('')
  const [showImport, setShowImport] = useState(false)
  const [importPem, setImportPem] = useState('')
  const [syncing, setSyncing] = useState(false)

  const handleSync = async () => {
    setSyncing(true)
    try {
      await certificateApi.syncNow()
      toast.success('cert-manager inventory refreshed')
      await loadCertificates()
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Sync failed')
    } finally {
      setSyncing(false)
    }
  }

  const handleImport = async () => {
    try {
      const r = await certificateApi.importCertificate(importPem)
      toast.success(`${r.certificates.length} certificate(s) imported`)
      setShowImport(false)
      setImportPem('')
      loadCertificates()
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Import failed')
    }
  }

  const loadCertificates = async () => {
    try {
      const response = await certificateApi.listCertificates({ limit: 1000 })
      setCertificates(response.certificates || [])
    } catch (error) {
      console.error('Failed to load certificates:', error)
      toast.error('Failed to load certificates')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadCertificates()
  }, [])

  const handleRenew = async (cert: Certificate) => {
    if (
      !confirm(
        `Renewing ${cert.cn} issues a brand new certificate and private key -- the old one still exists at the CA until it expires or is separately revoked. The new cert/key will download immediately; there is no way to get it again later. Continue?`
      )
    ) {
      return
    }

    try {
      const response = await certificateApi.renewCertificate(cert.id)
      if (response.download) {
        downloadBase64File(response.download.data, response.download.filename, response.download.mime_type)
      }
      toast.success('Certificate renewed -- new cert/key downloaded')
      loadCertificates()
    } catch (error: any) {
      console.error('Failed to renew certificate:', error)
      toast.error(error.response?.data?.error || 'Failed to renew certificate')
    }
  }

  const handleRevoke = async (cert: Certificate) => {
    if (!confirm(`Are you sure you want to revoke certificate for ${cert.cn}?`)) {
      return
    }

    try {
      await certificateApi.revokeCertificate(cert.id)
      toast.success('Certificate revoked successfully!')
      loadCertificates()
    } catch (error: any) {
      console.error('Failed to revoke certificate:', error)
      toast.error(error.response?.data?.error || 'Failed to revoke certificate')
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard!')
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'revoked':
        return <X className="h-4 w-4 text-red-500" />
      case 'expired':
        return <Clock className="h-4 w-4 text-gray-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getExpiryColor = (notAfter: string) => {
    const status = getExpiryStatus(notAfter)
    switch (status) {
      case 'critical':
        return 'text-red-600 bg-red-50'
      case 'warning':
        return 'text-yellow-600 bg-yellow-50'
      case 'expired':
        return 'text-gray-500 bg-gray-50'
      default:
        return 'text-green-600 bg-green-50'
    }
  }

  const filteredCertificates = certificates.filter((cert: Certificate) => {
    const matchesSearch = cert.cn.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cert.sans.some((san: string) => san.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesStatus = !statusFilter ||
      (statusFilter === 'expiring'
        ? cert.status === 'active' && getDaysUntilExpiry(cert.not_after) <= 30
        : cert.status === statusFilter)
    const matchesSource = !sourceFilter || cert.source === sourceFilter
    return matchesSearch && matchesStatus && matchesSource
  })

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center">
            <Link
              href="/"
              className="text-blue-600 hover:text-blue-500 text-sm font-medium"
            >
              ← Back to Dashboard
            </Link>
          </div>
          <h1 className="mt-4 text-3xl font-bold text-gray-900">Certificate Inventory</h1>
          <p className="mt-2 text-gray-600">Manage all your certificates</p>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label htmlFor="search" className="block text-sm font-medium text-gray-700">
                  Search
                </label>
                <div className="mt-1 relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    id="search"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                    placeholder="Search by CN or SANs..."
                  />
                </div>
              </div>
              <div>
                <label htmlFor="status" className="block text-sm font-medium text-gray-700">
                  Status
                </label>
                <select
                  id="status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                >
                  <option value="">All Statuses</option>
                  <option value="active">Active</option>
                  <option value="expiring">Expiring within 30 days</option>
                  <option value="revoked">Revoked</option>
                  <option value="expired">Expired</option>
                </select>
              </div>
              <div>
                <label htmlFor="source" className="block text-sm font-medium text-gray-700">
                  Source
                </label>
                <select
                  id="source"
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                >
                  <option value="">All sources</option>
                  <option value="ui">Issued here</option>
                  <option value="cert-manager">cert-manager</option>
                  <option value="import">Imported</option>
                </select>
              </div>
              <div className="flex items-end">
                <button
                  onClick={() => {
                    setSearchTerm('')
                    setStatusFilter('')
                    setSourceFilter('')
                  }}
                  className="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                >
                  <Filter className="h-4 w-4 mr-2" />
                  Clear Filters
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Certificates Table */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-medium text-gray-900">
              Certificates ({filteredCertificates.length})
            </h2>
            {isAdmin && (
              <div className="flex space-x-2">
                <button
                  onClick={handleSync}
                  disabled={syncing}
                  className="inline-flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  title="Re-read the cert-manager Certificates issued by step-ca"
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${syncing ? 'animate-spin' : ''}`} />
                  Sync cert-manager
                </button>
                <button
                  onClick={() => setShowImport(true)}
                  className="inline-flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50"
                >
                  <Upload className="h-4 w-4 mr-2" />
                  Import PEM
                </button>
              </div>
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Certificate
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Expires
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Days Left
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredCertificates.map((cert: Certificate) => (
                  <tr key={cert.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{cert.cn}</div>
                        {cert.sans && cert.sans.length > 0 && (
                          <div className="text-sm text-gray-500">
                            {cert.sans.slice(0, 2).join(', ')}
                            {cert.sans.length > 2 && ` +${cert.sans.length - 2} more`}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(cert.status)}
                        <span className="ml-2 text-sm text-gray-900 capitalize">{cert.status}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {formatDate(cert.not_after)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getExpiryColor(cert.not_after)}`}>
                        {getDaysUntilExpiry(cert.not_after)} days
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {cert.source === 'ui' ? `UI${cert.profile ? ' / ' + cert.profile : ''}` : cert.source === 'cert-manager' ? `cert-manager${cert.external_ref ? ' (' + cert.external_ref + ')' : ''}` : cert.source}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        {isAdmin && cert.status === 'active' && cert.source !== 'cert-manager' && (
                          <>
                            {cert.source === 'ui' && (
                              <button
                                onClick={() => handleRenew(cert)}
                                className="text-blue-600 hover:text-blue-900"
                                title="Renew Certificate"
                              >
                                <RotateCcw className="h-4 w-4" />
                              </button>
                            )}
                            <button
                              onClick={() => handleRevoke(cert)}
                              className="text-red-600 hover:text-red-900"
                              title="Revoke Certificate"
                            >
                              <X className="h-4 w-4" />
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => setSelectedCert(cert)}
                          className="text-gray-600 hover:text-gray-900"
                          title="View Details"
                        >
                          <Shield className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Import modal */}
        {showImport && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-[40rem] max-w-full shadow-lg rounded-md bg-white">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900">Import certificates</h3>
                <button onClick={() => setShowImport(false)} className="text-gray-400 hover:text-gray-600">
                  <X className="h-6 w-6" />
                </button>
              </div>
              <p className="text-sm text-gray-600 mb-2">
                Paste one or more PEM certificates (leaf certificates only are recorded). They appear in the
                inventory and its expiry monitoring; no key is needed.
              </p>
              <textarea
                value={importPem}
                onChange={(e) => setImportPem(e.target.value)}
                rows={12}
                className="block w-full border-gray-300 rounded-md shadow-sm font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
              />
              <div className="mt-4 flex justify-end space-x-3">
                <button onClick={() => setShowImport(false)} className="px-4 py-2 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50">
                  Cancel
                </button>
                <button onClick={handleImport} disabled={!importPem.trim()} className="px-4 py-2 rounded-md text-sm text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50">
                  Import
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Certificate Details Modal */}
        {selectedCert && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
              <div className="mt-3">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-medium text-gray-900">Certificate Details</h3>
                  <button
                    onClick={() => setSelectedCert(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="h-6 w-6" />
                  </button>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium text-gray-500">Common Name</label>
                    <p className="text-sm text-gray-900">{selectedCert.cn}</p>
                  </div>
                  {selectedCert.sans && selectedCert.sans.length > 0 && (
                    <div>
                      <label className="text-sm font-medium text-gray-500">Subject Alternative Names</label>
                      <ul className="text-sm text-gray-900">
                        {selectedCert.sans.map((san, index) => (
                          <li key={index}>• {san}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div>
                    <label className="text-sm font-medium text-gray-500">Serial Number</label>
                    <div className="flex items-center">
                      <p className="text-sm text-gray-900 font-mono break-all">{selectedCert.serial}</p>
                      <button
                        onClick={() => copyToClipboard(selectedCert.serial)}
                        className="ml-2 flex-shrink-0 text-gray-400 hover:text-gray-600"
                        title="Copy serial number"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Issued By</label>
                    <p className="text-sm text-gray-900">{selectedCert.owner || 'Unknown'}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Status</label>
                    <p className="text-sm text-gray-900 capitalize">{selectedCert.status}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Expires</label>
                    <p className="text-sm text-gray-900">{formatDate(selectedCert.not_after)}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Source / profile</label>
                    <p className="text-sm text-gray-900">{selectedCert.source}{selectedCert.profile ? ` / ${selectedCert.profile}` : ''}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Created</label>
                    <p className="text-sm text-gray-900">{formatDate(selectedCert.created_at)}</p>
                  </div>
                </div>
                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    onClick={() => setSelectedCert(null)}
                    className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
