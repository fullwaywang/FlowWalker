function [] = outcome(bnd0,bnd1,bnd2,bnd3,bnd4,bnd5)
%Evaluation
bnd0=unique(bnd0);
cand=[bnd1,bnd2,bnd3,bnd4,bnd5];
found=intersect(bnd0,cand);
falser=setdiff(bnd1,bnd0);

base=size(bnd0,2);
size(found,2)/base
size(falser,2)/base

end