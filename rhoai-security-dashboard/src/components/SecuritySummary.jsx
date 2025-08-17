import React from 'react'
import {
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  Title,
  Label
} from '@patternfly/react-core'
import { calculateSecurityMetrics, getGradeColor, getCVECountColor } from '../utils/dataProcessing'

const SecuritySummary = ({ data }) => {
  const metrics = calculateSecurityMetrics(data)

  const summaryCards = [
    {
      title: 'Total Images Analyzed',
      value: metrics.totalImages,
      description: 'Container images in this release',
      color: 'blue'
    },
    {
      title: 'Total Unique CVEs',
      value: metrics.totalCVEs,
      description: 'Security vulnerabilities found',
      color: getCVECountColor(metrics.totalCVEs)
    },
    {
      title: 'Worst Security Grade',
      value: metrics.worstGrade,
      description: 'Lowest freshness grade found',
      color: getGradeColor(metrics.worstGrade)
    },
    {
      title: 'Most Vulnerable Image',
      value: `${metrics.mostVulnerable.cveCount} CVEs`,
      description: metrics.mostVulnerable.name,
      color: getCVECountColor(metrics.mostVulnerable.cveCount)
    }
  ]

  return (
    <>
      <Title headingLevel="h2" size="xl" style={{ marginBottom: '1rem' }}>
        Security Overview
      </Title>
      <Grid hasGutter>
        {summaryCards.map((card, index) => (
          <GridItem key={index} xl={3} lg={6} md={6} sm={12}>
            <Card isFullHeight>
              <CardTitle>
                <Title headingLevel="h3" size="md">
                  {card.title}
                </Title>
              </CardTitle>
              <CardBody>
                <div style={{ marginBottom: '0.5rem' }}>
                  <Label color={card.color} variant="filled" style={{ fontSize: '1.5rem', padding: '0.5rem 1rem' }}>
                    {card.value}
                  </Label>
                </div>
                <div style={{ fontSize: '0.875rem', color: '#6a6e73' }}>
                  {card.description}
                </div>
              </CardBody>
            </Card>
          </GridItem>
        ))}
      </Grid>
    </>
  )
}

export default SecuritySummary