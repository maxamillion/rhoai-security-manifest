import { useState, useEffect } from 'react'
import '@patternfly/react-core/dist/styles/base.css'
import { 
  Page, 
  PageSection, 
  Title, 
  Masthead,
  MastheadMain,
  MastheadContent,
  Flex,
  FlexItem
} from '@patternfly/react-core'
import Dashboard from './components/Dashboard'

function App() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const loadData = async () => {
      try {
        const response = await fetch('/sample_data.json')
        if (!response.ok) {
          throw new Error('Failed to load security data')
        }
        const jsonData = await response.json()
        setData(jsonData)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [])

  const masthead = (
    <Masthead>
      <MastheadMain>
        <Flex alignItems={{ default: 'alignItemsCenter' }}>
          <FlexItem>
            <Title headingLevel="h1" size="2xl">
              Red Hat OpenShift AI Security Dashboard
            </Title>
          </FlexItem>
        </Flex>
      </MastheadMain>
      <MastheadContent>
        {data && (
          <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsMd' }}>
            <FlexItem>
              <strong>Release:</strong> {data.metadata.release}
            </FlexItem>
            <FlexItem>
              <strong>Generated:</strong> {new Date(data.metadata.generated_at).toLocaleString()}
            </FlexItem>
          </Flex>
        )}
      </MastheadContent>
    </Masthead>
  )

  return (
    <Page masthead={masthead}>
      <PageSection>
        {loading && <div>Loading security data...</div>}
        {error && <div>Error: {error}</div>}
        {data && <Dashboard data={data} />}
      </PageSection>
    </Page>
  )
}

export default App
