import React, { useState, useMemo } from 'react'
import {
  Card,
  CardBody,
  CardTitle,
  Title,
  SearchInput,
  Button,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
  Pagination,
  List,
  ListItem,
  Flex,
  FlexItem
} from '@patternfly/react-core'
import { ExternalLinkAltIcon } from '@patternfly/react-icons'

const CVEList = ({ data }) => {
  const [searchValue, setSearchValue] = useState('')
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(20)

  const filteredCVEs = useMemo(() => {
    if (!data.unique_cves) return []
    
    return data.unique_cves.filter(cve => {
      const cveId = cve.split('/').pop().toLowerCase()
      return cveId.includes(searchValue.toLowerCase())
    })
  }, [data.unique_cves, searchValue])

  const paginatedCVEs = useMemo(() => {
    const start = (page - 1) * perPage
    return filteredCVEs.slice(start, start + perPage)
  }, [filteredCVEs, page, perPage])

  const handleSearchChange = (value) => {
    setSearchValue(value)
    setPage(1) // Reset to first page when searching
  }

  const clearSearch = () => {
    setSearchValue('')
    setPage(1)
  }

  return (
    <Card>
      <CardTitle>
        <Title headingLevel="h2" size="xl">
          Complete CVE List ({data.unique_cves ? data.unique_cves.length : 0} unique vulnerabilities)
        </Title>
      </CardTitle>
      <CardBody>
        <Toolbar>
          <ToolbarContent>
            <ToolbarGroup>
              <ToolbarItem widths={{ default: '300px' }}>
                <SearchInput
                  placeholder="Search CVEs..."
                  value={searchValue}
                  onChange={(_event, value) => handleSearchChange(value)}
                  onClear={clearSearch}
                />
              </ToolbarItem>
            </ToolbarGroup>
            <ToolbarItem variant="pagination">
              <Pagination
                itemCount={filteredCVEs.length}
                perPage={perPage}
                page={page}
                onSetPage={(_event, pageNumber) => setPage(pageNumber)}
                onPerPageSelect={(_event, newPerPage) => {
                  setPerPage(newPerPage)
                  setPage(1)
                }}
                variant="top"
                isCompact
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>

        {filteredCVEs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: '#6a6e73' }}>
            {searchValue ? 'No CVEs found matching your search.' : 'No CVEs available.'}
          </div>
        ) : (
          <>
            <List isPlain isBordered>
              {paginatedCVEs.map((cve, index) => {
                const cveId = cve.split('/').pop()
                return (
                  <ListItem key={index}>
                    <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsMd' }}>
                      <FlexItem>
                        <strong>{cveId}</strong>
                      </FlexItem>
                      <FlexItem>
                        <Button
                          variant="link"
                          icon={<ExternalLinkAltIcon />}
                          iconPosition="right"
                          component="a"
                          href={cve}
                          target="_blank"
                          rel="noopener noreferrer"
                          size="sm"
                        >
                          View Details
                        </Button>
                      </FlexItem>
                    </Flex>
                  </ListItem>
                )
              })}
            </List>

            <Pagination
              itemCount={filteredCVEs.length}
              perPage={perPage}
              page={page}
              onSetPage={(_event, pageNumber) => setPage(pageNumber)}
              onPerPageSelect={(_event, newPerPage) => {
                setPerPage(newPerPage)
                setPage(1)
              }}
              variant="bottom"
              style={{ marginTop: '1rem' }}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}

export default CVEList