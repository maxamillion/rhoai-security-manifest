// Data processing utilities for RHOAI security dashboard

export const getGradeColor = (grade) => {
  switch (grade) {
    case 'A': return 'green'
    case 'B': return 'gold'
    case 'C': return 'orange'
    case 'D': return 'red'
    case 'F': return 'red'
    default: return 'grey'
  }
}

export const getCVECountColor = (count) => {
  if (count === 0) return 'green'
  if (count < 5) return 'gold'
  if (count < 15) return 'orange'
  return 'red'
}

export const calculateGradeDistribution = (images) => {
  const distribution = { A: 0, B: 0, C: 0, D: 0, F: 0 }
  
  images.forEach(image => {
    if (image.freshness_grades && image.freshness_grades[0]) {
      const grade = image.freshness_grades[0].grade
      if (distribution.hasOwnProperty(grade)) {
        distribution[grade]++
      }
    }
  })
  
  return Object.entries(distribution).map(([grade, count]) => ({
    x: grade,
    y: count,
    label: `${grade}: ${count}`
  }))
}

export const getMostVulnerableImages = (images, limit = 10) => {
  return images
    .map(image => ({
      name: getImageName(image),
      cveCount: image.cves ? image.cves.length : 0,
      grade: image.freshness_grades && image.freshness_grades[0] ? image.freshness_grades[0].grade : 'Unknown'
    }))
    .sort((a, b) => b.cveCount - a.cveCount)
    .slice(0, limit)
    .map(item => ({
      x: item.cveCount,
      y: item.name,
      label: `${item.name}: ${item.cveCount} CVEs`
    }))
}

export const getImageName = (image) => {
  if (image.repositories && image.repositories[0]) {
    const repo = image.repositories[0]
    const registry = repo.registry || ''
    const repository = repo.repository || ''
    
    if (registry && repository) {
      const baseUrl = `${registry}/${repository}`
      // Truncate long registry URLs for display
      if (baseUrl.length > 60) {
        const parts = repository.split('/')
        const shortName = parts[parts.length - 1] // Get the last part
        return `${registry.split('.')[0]}.../${shortName}`
      }
      return baseUrl
    }
  }
  
  return image._id || 'Unknown'
}

export const getAdvisoryUrl = (image) => {
  if (image.repositories && image.repositories[0] && image.repositories[0]._links && image.repositories[0]._links.image_advisory) {
    const advisoryId = image.repositories[0]._links.image_advisory.href.split('/').pop()
    return `https://access.redhat.com/errata/${advisoryId}`
  }
  return null
}

export const formatDate = (dateString) => {
  if (!dateString) return 'Unknown'
  return new Date(dateString).toLocaleDateString()
}

export const calculateSecurityMetrics = (data) => {
  const { images, unique_cves, metadata } = data
  
  // Calculate worst security grade
  const grades = images
    .map(img => img.freshness_grades && img.freshness_grades[0] ? img.freshness_grades[0].grade : 'F')
    .sort()
  const worstGrade = grades[grades.length - 1] || 'Unknown'
  
  // Find most vulnerable image
  const mostVulnerable = images.reduce((max, current) => {
    const currentCVEs = current.cves ? current.cves.length : 0
    const maxCVEs = max.cves ? max.cves.length : 0
    return currentCVEs > maxCVEs ? current : max
  }, images[0])
  
  // Grade distribution
  const gradeDistribution = calculateGradeDistribution(images)
  
  return {
    totalImages: metadata.total_images,
    totalCVEs: metadata.total_unique_cves,
    worstGrade,
    mostVulnerable: {
      name: getImageName(mostVulnerable),
      cveCount: mostVulnerable.cves ? mostVulnerable.cves.length : 0
    },
    gradeDistribution
  }
}