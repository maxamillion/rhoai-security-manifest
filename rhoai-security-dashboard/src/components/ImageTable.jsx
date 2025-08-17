import React, { useState, useMemo } from 'react'
import {
  Card,
  CardBody,
  CardTitle,
  Title,
  Label,
  Button,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
  Select,
  SelectOption,
  SelectList,
  MenuToggle,
  Pagination
} from '@patternfly/react-core'
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  ExpandableRowContent
} from '@patternfly/react-table'
import { ExternalLinkAltIcon, AngleDownIcon, AngleRightIcon } from '@patternfly/react-icons'
import { getImageName, getAdvisoryUrl, formatDate, getGradeColor, getCVECountColor } from '../utils/dataProcessing'

const ImageTable = ({ data }) => {
  const [sortBy, setSortBy] = useState({ index: 0, direction: 'asc' })
  const [filterGrade, setFilterGrade] = useState('all')
  const [isGradeSelectOpen, setIsGradeSelectOpen] = useState(false)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(10)
  const [expandedRows, setExpandedRows] = useState(new Set())

  const columns = [
    { title: 'Image Name', sortable: true },
    { title: 'Freshness Grade', sortable: true },
    { title: 'CVE Count', sortable: true },
    { title: 'Advisory', sortable: false },
    { title: 'Creation Date', sortable: true },
    { title: '', sortable: false } // Expand button column
  ]

  const processedData = useMemo(() => {
    let filtered = data.images.filter(image => {
      if (filterGrade === 'all') return true
      const grade = image.freshness_grades && image.freshness_grades[0] ? image.freshness_grades[0].grade : 'Unknown'
      return grade === filterGrade
    })

    // Sort data
    const sortedData = [...filtered].sort((a, b) => {
      let aVal, bVal
      
      switch (sortBy.index) {
        case 0: // Image Name
          aVal = getImageName(a)
          bVal = getImageName(b)
          break
        case 1: // Freshness Grade
          aVal = a.freshness_grades && a.freshness_grades[0] ? a.freshness_grades[0].grade : 'Z'
          bVal = b.freshness_grades && b.freshness_grades[0] ? b.freshness_grades[0].grade : 'Z'
          break
        case 2: // CVE Count
          aVal = a.cves ? a.cves.length : 0
          bVal = b.cves ? b.cves.length : 0
          break
        case 4: // Creation Date
          aVal = new Date(a.creation_date || 0)
          bVal = new Date(b.creation_date || 0)
          break
        default:
          return 0
      }

      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase()
        bVal = bVal.toLowerCase()
      }

      if (sortBy.direction === 'asc') {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0
      }
    })

    return sortedData
  }, [data.images, sortBy, filterGrade])

  const paginatedData = useMemo(() => {
    const start = (page - 1) * perPage
    return processedData.slice(start, start + perPage)
  }, [processedData, page, perPage])

  const handleSort = (columnIndex) => {
    if (!columns[columnIndex].sortable) return
    
    setSortBy(prev => ({
      index: columnIndex,
      direction: prev.index === columnIndex && prev.direction === 'asc' ? 'desc' : 'asc'
    }))
  }

  const getSortParams = (columnIndex) => {
    return columns[columnIndex].sortable ? {
      sort: {
        sortBy: {
          index: sortBy.index,
          direction: sortBy.direction
        },
        onSort: () => handleSort(columnIndex),
        columnIndex
      }
    } : {}
  }

  const toggleExpanded = (imageId) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev)
      if (newSet.has(imageId)) {
        newSet.delete(imageId)
      } else {
        newSet.add(imageId)
      }
      return newSet
    })
  }

  const gradeOptions = [
    { value: 'all', label: 'All Grades' },
    { value: 'A', label: 'Grade A' },
    { value: 'B', label: 'Grade B' },
    { value: 'C', label: 'Grade C' },
    { value: 'D', label: 'Grade D' },
    { value: 'F', label: 'Grade F' }
  ]

  return (
    <Card>
      <CardTitle>
        <Title headingLevel="h2" size="xl">
          Container Images Details
        </Title>
      </CardTitle>
      <CardBody>
        <Toolbar>
          <ToolbarContent>
            <ToolbarGroup>
              <ToolbarItem>
                <Select
                  isOpen={isGradeSelectOpen}
                  selected={filterGrade}
                  onSelect={(_event, value) => {
                    setFilterGrade(value)
                    setIsGradeSelectOpen(false)
                    setPage(1) // Reset to first page when filtering
                  }}
                  onOpenChange={setIsGradeSelectOpen}
                  toggle={toggleRef => (
                    <MenuToggle ref={toggleRef} onClick={() => setIsGradeSelectOpen(!isGradeSelectOpen)}>
                      {gradeOptions.find(opt => opt.value === filterGrade)?.label}
                    </MenuToggle>
                  )}
                >
                  <SelectList>
                    {gradeOptions.map(option => (
                      <SelectOption key={option.value} value={option.value}>
                        {option.label}
                      </SelectOption>
                    ))}
                  </SelectList>
                </Select>
              </ToolbarItem>
            </ToolbarGroup>
            <ToolbarItem variant="pagination">
              <Pagination
                itemCount={processedData.length}
                perPage={perPage}
                page={page}
                onSetPage={(_event, pageNumber) => setPage(pageNumber)}
                onPerPageSelect={(_event, newPerPage) => {
                  setPerPage(newPerPage)
                  setPage(1)
                }}
                variant="top"
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>

        <Table aria-label="Container images table">
          <Thead>
            <Tr>
              {columns.map((column, index) => (
                <Th key={index} {...getSortParams(index)}>
                  {column.title}
                </Th>
              ))}
            </Tr>
          </Thead>
          <Tbody>
            {paginatedData.map((image, index) => {
              const imageId = image._id
              const isExpanded = expandedRows.has(imageId)
              const imageName = getImageName(image)
              const grade = image.freshness_grades && image.freshness_grades[0] ? image.freshness_grades[0].grade : 'Unknown'
              const cveCount = image.cves ? image.cves.length : 0
              const advisoryUrl = getAdvisoryUrl(image)
              const creationDate = formatDate(image.creation_date)

              return (
                <React.Fragment key={imageId}>
                  <Tr>
                    <Td dataLabel="Image Name">{imageName}</Td>
                    <Td dataLabel="Freshness Grade">
                      <Label color={getGradeColor(grade)}>{grade}</Label>
                    </Td>
                    <Td dataLabel="CVE Count">
                      <Label color={getCVECountColor(cveCount)}>{cveCount}</Label>
                    </Td>
                    <Td dataLabel="Advisory">
                      {advisoryUrl && (
                        <Button 
                          variant="link" 
                          icon={<ExternalLinkAltIcon />} 
                          iconPosition="right"
                          component="a"
                          href={advisoryUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          View Advisory
                        </Button>
                      )}
                    </Td>
                    <Td dataLabel="Creation Date">{creationDate}</Td>
                    <Td>
                      {cveCount > 0 && (
                        <Button
                          variant="plain"
                          aria-label={`${isExpanded ? 'Collapse' : 'Expand'} CVE details`}
                          onClick={() => toggleExpanded(imageId)}
                        >
                          {isExpanded ? <AngleDownIcon /> : <AngleRightIcon />}
                        </Button>
                      )}
                    </Td>
                  </Tr>
                  {isExpanded && cveCount > 0 && (
                    <Tr isExpanded>
                      <Td colSpan={6}>
                        <ExpandableRowContent>
                          <div style={{ padding: '1rem' }}>
                            <Title headingLevel="h4" size="md" style={{ marginBottom: '0.5rem' }}>
                              CVEs ({cveCount})
                            </Title>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                              {image.cves.map((cve, cveIndex) => {
                                const cveId = cve.split('/').pop()
                                return (
                                  <Button
                                    key={cveIndex}
                                    variant="link"
                                    component="a"
                                    href={cve}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    size="sm"
                                  >
                                    {cveId}
                                  </Button>
                                )
                              })}
                            </div>
                          </div>
                        </ExpandableRowContent>
                      </Td>
                    </Tr>
                  )}
                </React.Fragment>
              )
            })}
          </Tbody>
        </Table>

        <Pagination
          itemCount={processedData.length}
          perPage={perPage}
          page={page}
          onSetPage={(_event, pageNumber) => setPage(pageNumber)}
          onPerPageSelect={(_event, newPerPage) => {
            setPerPage(newPerPage)
            setPage(1)
          }}
          variant="bottom"
        />
      </CardBody>
    </Card>
  )
}

export default ImageTable