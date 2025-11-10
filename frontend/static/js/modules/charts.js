/**
 * Charts Module
 * Utilities for creating and managing charts
 */

export class ChartManager {
    constructor() {
        this.charts = new Map();
    }
    
    createLineChart(canvasId, data, options = {}) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        
        const ctx = canvas.getContext('2d');
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            ...options
        };
        
        const chart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: defaultOptions
        });
        
        this.charts.set(canvasId, chart);
        return chart;
    }
    
    createDoughnutChart(canvasId, data, options = {}) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        
        const ctx = canvas.getContext('2d');
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            ...options
        };
        
        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: defaultOptions
        });
        
        this.charts.set(canvasId, chart);
        return chart;
    }
    
    createBarChart(canvasId, data, options = {}) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        
        const ctx = canvas.getContext('2d');
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            ...options
        };
        
        const chart = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: defaultOptions
        });
        
        this.charts.set(canvasId, chart);
        return chart;
    }
    
    updateChart(canvasId, data) {
        const chart = this.charts.get(canvasId);
        if (chart) {
            chart.data = data;
            chart.update();
        }
    }
    
    destroyChart(canvasId) {
        const chart = this.charts.get(canvasId);
        if (chart) {
            chart.destroy();
            this.charts.delete(canvasId);
        }
    }
    
    destroyAll() {
        this.charts.forEach((chart, id) => {
            chart.destroy();
        });
        this.charts.clear();
    }
}

// Export singleton instance
export const chartManager = new ChartManager();

