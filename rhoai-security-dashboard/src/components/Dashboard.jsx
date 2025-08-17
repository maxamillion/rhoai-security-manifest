import React from 'react'
import { 
  Grid, 
  GridItem,
  PageSection,
  PageSectionVariants 
} from '@patternfly/react-core'
import SecuritySummary from './SecuritySummary'
import SecurityCharts from './SecurityCharts'
import ImageTable from './ImageTable'
import CVEList from './CVEList'

const Dashboard = ({ data }) => {
  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <SecuritySummary data={data} />
      </PageSection>
      
      <PageSection>
        <Grid hasGutter>
          <GridItem span={12}>
            <SecurityCharts data={data} />
          </GridItem>
          
          <GridItem span={12}>
            <ImageTable data={data} />
          </GridItem>
          
          <GridItem span={12}>
            <CVEList data={data} />
          </GridItem>
        </Grid>
      </PageSection>
    </>
  )
}

export default Dashboard