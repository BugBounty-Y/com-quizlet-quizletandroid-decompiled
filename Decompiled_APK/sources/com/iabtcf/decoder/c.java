package com.iabtcf.decoder;

import com.iabtcf.utils.l;
import com.iabtcf.utils.n;
import java.time.Instant;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/* loaded from: classes2.dex */
public final class c implements b {
    public final com.iabtcf.utils.a a;

    public c(com.iabtcf.utils.a aVar) {
        this.a = aVar;
    }

    @Override // com.iabtcf.decoder.b
    public final List a() {
        throw new UnsupportedOperationException();
    }

    @Override // com.iabtcf.decoder.b
    public final n b() {
        return e.g(this.a, l.i1);
    }

    @Override // com.iabtcf.decoder.b
    public final n c() {
        l lVar = l.j1;
        l lVar2 = l.l1;
        BitSet bitSet = new BitSet();
        com.iabtcf.utils.a aVar = this.a;
        int iF = aVar.f(lVar.b(aVar));
        if (aVar.b(lVar.b(aVar) + lVar.a(aVar))) {
            boolean zC = aVar.c(l.m1);
            e.D(aVar, bitSet, l.n1.b(aVar), Optional.of(lVar));
            if (zC) {
                bitSet.flip(1, iF + 1);
            }
        } else {
            for (int i = 0; i < iF; i++) {
                if (aVar.b(lVar2.b(aVar) + i)) {
                    bitSet.set(i + 1);
                }
            }
        }
        return new com.iabtcf.utils.c((BitSet) bitSet.clone());
    }

    @Override // com.iabtcf.decoder.b
    public final int e() {
        return this.a.e(l.h1);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || c.class != obj.getClass()) {
            return false;
        }
        c cVar = (c) obj;
        if (f() != cVar.f() || !Objects.equals(g(), cVar.g()) || !Objects.equals(i(), cVar.i())) {
            return false;
        }
        com.iabtcf.utils.a aVar = this.a;
        l lVar = l.d1;
        int iE = aVar.e(lVar);
        com.iabtcf.utils.a aVar2 = cVar.a;
        if (iE != aVar2.e(lVar)) {
            return false;
        }
        l lVar2 = l.e1;
        if (aVar.e(lVar2) != aVar2.e(lVar2)) {
            return false;
        }
        l lVar3 = l.f1;
        if (aVar.i(lVar3) != aVar2.i(lVar3)) {
            return false;
        }
        l lVar4 = l.g1;
        return Objects.equals(aVar.k(lVar4), aVar2.k(lVar4)) && e() == cVar.e() && c().equals(cVar.c()) && h() == cVar.h() && b().equals(cVar.b());
    }

    @Override // com.iabtcf.decoder.b
    public final int f() {
        return this.a.i(l.Y);
    }

    public final Instant g() {
        return Instant.ofEpochMilli(this.a.g(l.Z) * 100);
    }

    public final boolean h() {
        l lVar = l.k1;
        com.iabtcf.utils.a aVar = this.a;
        return aVar.c(lVar) && aVar.c(l.m1);
    }

    public final int hashCode() {
        Integer numValueOf = Integer.valueOf(f());
        Instant instantG = g();
        Instant instantI = i();
        com.iabtcf.utils.a aVar = this.a;
        return Objects.hash(numValueOf, instantG, instantI, Integer.valueOf(aVar.e(l.d1)), Integer.valueOf(aVar.e(l.e1)), Integer.valueOf(aVar.i(l.f1)), aVar.k(l.g1), Integer.valueOf(e()), c(), Boolean.valueOf(h()), b());
    }

    public final Instant i() {
        return Instant.ofEpochMilli(this.a.g(l.c1) * 100);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TCStringV1 [getVersion()=");
        sb.append(f());
        sb.append(", getCreated()=");
        sb.append(g());
        sb.append(", getLastUpdated()=");
        sb.append(i());
        sb.append(", getCmpId()=");
        com.iabtcf.utils.a aVar = this.a;
        sb.append(aVar.e(l.d1));
        sb.append(", getCmpVersion()=");
        sb.append(aVar.e(l.e1));
        sb.append(", getConsentScreen()=");
        sb.append((int) aVar.i(l.f1));
        sb.append(", getConsentLanguage()=");
        sb.append(aVar.k(l.g1));
        sb.append(", getVendorListVersion()=");
        sb.append(e());
        sb.append(", getVendorConsent()=");
        sb.append(c());
        sb.append(", getDefaultVendorConsent()=");
        sb.append(h());
        sb.append(", getPurposesConsent()=");
        sb.append(b());
        sb.append("]");
        return sb.toString();
    }
}
