import React from 'react'
import {
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  Title
} from '@patternfly/react-core'
import {
  VictoryPie,
  VictoryBar,
  VictoryChart,
  VictoryAxis,
  VictoryContainer,
  VictoryTheme
} from 'victory'
import { calculateGradeDistribution, getMostVulnerableImages } from '../utils/dataProcessing'

const SecurityCharts = ({ data }) => {
  const gradeData = calculateGradeDistribution(data.images)
  const vulnerableImages = getMostVulnerableImages(data.images, 8)

  // Calculate total for donut chart
  const totalImages = gradeData.reduce((sum, item) => sum + item.y, 0)

  // Filter out grades with 0 count for cleaner donut chart
  const filteredGradeData = gradeData.filter(item => item.y > 0)

  // Grade colors matching our utility function
  const gradeColors = {
    A: '#3E8635', // green
    B: '#F0AB00', // gold
    C: '#EC7A08', // orange
    D: '#C9190B', // red
    F: '#C9190B'  // red
  }

  const donutColorScale = filteredGradeData.map(item => gradeColors[item.x] || '#6A6E73')

  return (
    <>
      <Title headingLevel="h2" size="xl" style={{ marginBottom: '1rem' }}>
        Security Analysis
      </Title>
      <Grid hasGutter>
        <GridItem xl={6} lg={12} md={12} sm={12}>
          <Card isFullHeight>
            <CardTitle>
              <Title headingLevel="h3" size="md">
                Security Grade Distribution
              </Title>
            </CardTitle>
            <CardBody>
              {filteredGradeData.length > 0 ? (
                <div style={{ height: '300px' }}>
                  <VictoryPie
                    data={filteredGradeData}
                    height={300}
                    width={500}
                    labelComponent={<div />}
                    colorScale={donutColorScale}
                    innerRadius={60}
                    containerComponent={
                      <VictoryContainer responsive={true} />
                    }
                    padding={{ left: 50, right: 150, top: 50, bottom: 50 }}
                  />
                  <div style={{ marginTop: '1rem' }}>
                    {filteredGradeData.map((item, index) => (
                      <div key={item.x} style={{ display: 'inline-block', marginRight: '1rem', marginBottom: '0.5rem' }}>
                        <span 
                          style={{ 
                            display: 'inline-block', 
                            width: '12px', 
                            height: '12px', 
                            backgroundColor: donutColorScale[index],
                            marginRight: '0.5rem' 
                          }}
                        />
                        <span>{item.x}: {item.y} images</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div>No grade data available</div>
              )}
            </CardBody>
          </Card>
        </GridItem>

        <GridItem xl={6} lg={12} md={12} sm={12}>
          <Card isFullHeight>
            <CardTitle>
              <Title headingLevel="h3" size="md">
                Most Vulnerable Images (Top 8)
              </Title>
            </CardTitle>
            <CardBody>
              {vulnerableImages.length > 0 ? (
                <div style={{ height: '300px' }}>
                  <VictoryChart
                    horizontal
                    height={300}
                    width={500}
                    padding={{ left: 200, right: 50, top: 20, bottom: 40 }}
                    theme={VictoryTheme.material}
                    containerComponent={
                      <VictoryContainer responsive={true} />
                    }
                  >
                    <VictoryAxis dependentAxis />
                    <VictoryAxis />
                    <VictoryBar
                      data={vulnerableImages}
                      style={{
                        data: { fill: "#c43a31" }
                      }}
                    />
                  </VictoryChart>
                </div>
              ) : (
                <div>No vulnerability data available</div>
              )}
            </CardBody>
          </Card>
        </GridItem>
      </Grid>
    </>
  )
}

export default SecurityCharts