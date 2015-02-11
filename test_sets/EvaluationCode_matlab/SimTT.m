function [] = SimTT(mss, d_lea, bounds )
%Draw the SimTT figure
n=size(mss,2);

figure;
subplot(4,1,1),plot(mss),title('1. Unadjusted SimTT');
axis([0 n 0 1]);
set(gca,'XTick',bounds,'YTick',0:0.2:1,'FontSize',5,'XGrid','on');
mss=mss.*d_lea;

subplot(4,1,2),plot(mss),title('2. SimTT with d_{LEA} coefficient');
axis([0 n 0 1]);
set(gca,'XTick',bounds,'YTick',0:0.2:1,'FontSize',5,'XGrid','on');

dif1_mss=mss;
dif1_mss(1:end-1)=dif1_mss(1:end-1)-0.5.*mss(2:end);
dif1_mss(2:end)=dif1_mss(2:end)-0.5.*mss(1:end-1);

subplot(4,1,3),plot(dif1_mss),title('3. DIF_1');
axis([0 n -1 1]);
set(gca,'XTick',bounds,'YTick',0,'FontSize',5);
grid on;

dif2_mss=mss;
dif2_mss(1:end-2)=dif2_mss(1:end-2)-0.375.*mss(2:end-1)-0.125.*mss(3:end);
dif2_mss(3:end)=dif2_mss(3:end)-0.375.*mss(2:end-1)-0.125.*mss(1:end-2);
dif2_mss(1)=dif2_mss(1)-0.375.*mss(2)-0.125.*mss(3);
dif2_mss(2)=dif2_mss(2)-0.5.*mss(1);
dif2_mss(end)=dif2_mss(end)-0.375.*mss(end-1)-0.125.*mss(end-2);
dif2_mss(end-1)=dif2_mss(end-1)-0.5.*mss(end);

subplot(4,1,4),plot(dif2_mss),title('4. DIF_2');
axis([0 n -1 1]);
set(gca,'XTick',bounds,'YTick',0,'FontSize',5);
grid on;

% bound=[];
% for i=1:n
%     if dif2_mss(i)<0
%         bound=[bound i];
%     end
% end
% 
% tt=size(bound,2);
% for i=2:tt
%     if mss(bound(i))-mss(bound(i-1)) > 2*(mss(bound(i-1)+1)-mss(bound(i)))
%         bound(i)
%         bound=[bound(1:i-1) bound(i+1:end)];
%         tt=tt-1;
%         i=i-1;
%     end
% end

end

