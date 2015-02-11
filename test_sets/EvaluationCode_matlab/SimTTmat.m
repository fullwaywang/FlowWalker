function [] = SimTTmat(sim, bounds)
%Draw the SimTT matrix

figure;
imagesc(sim);
colormap(gray(64));
axis square;
axis xy;
set(gca, 'XTick',bounds, 'YTick',bounds, 'FontSize',5, 'YGrid','on');

end

