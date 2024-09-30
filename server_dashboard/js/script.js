particleground(document.getElementById('particles-foreground'), {
  dotColor: 'rgba(255, 255, 255, 1)',
  lineColor: 'rgba(255, 255, 255, 0.05)',
  minSpeedX: 0.3,
  maxSpeedX: 0.6,
  minSpeedY: 0.3,
  maxSpeedY: 0.6,
  density: 50000, // Um ponto a cada n pixels
  curvedLines: false,
  proximity: 250, // Distância entre partículas para unir linhas
  parallaxMultiplier: 10, // Menor o número, maior o efeito
  particleRadius: 4, // Tamanho das partículas
});

particleground(document.getElementById('particles-background'), {
  dotColor: 'rgba(255, 255, 255, 0.5)',
  lineColor: 'rgba(255, 255, 255, 0.05)',
  minSpeedX: 0.075,
  maxSpeedX: 0.15,
  minSpeedY: 0.075,
  maxSpeedY: 0.15,
  density: 30000, // Um ponto a cada n pixels
  curvedLines: false,
  proximity: 20, // Distância entre partículas para unir linhas
  parallaxMultiplier: 20, // Menor o número, maior o efeito
  particleRadius: 2, // Tamanho das partículas
});
