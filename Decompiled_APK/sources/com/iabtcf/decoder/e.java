package com.iabtcf.decoder;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.iabtcf.exceptions.InvalidRangeFieldException;
import com.iabtcf.utils.l;
import com.iabtcf.utils.n;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/* loaded from: classes2.dex */
public final class e implements b {
    public final com.iabtcf.utils.a A;
    public final List B;
    public int a;
    public Instant b;
    public Instant c;
    public int d;
    public int e;
    public int f;
    public String g;
    public int h;
    public int i;
    public boolean j;
    public boolean k;
    public com.iabtcf.utils.c l;
    public com.iabtcf.utils.c m;
    public com.iabtcf.utils.c n;
    public boolean o;
    public String p;
    public com.iabtcf.utils.c q;
    public com.iabtcf.utils.c r;
    public ArrayList s;
    public com.iabtcf.utils.c t;
    public com.iabtcf.utils.c u;
    public com.iabtcf.utils.c v;
    public com.iabtcf.utils.c w;
    public com.iabtcf.utils.c x;
    public com.iabtcf.utils.c y;
    public final EnumSet z = EnumSet.noneOf(l.class);

    public e(com.iabtcf.utils.a aVar, com.iabtcf.utils.a... aVarArr) {
        this.A = aVar;
        this.B = Arrays.asList(aVarArr);
    }

    public static int D(com.iabtcf.utils.a aVar, BitSet bitSet, int i, Optional optional) {
        int iD = aVar.d(i);
        int iA = l.K.a(aVar) + i;
        Integer num = (Integer) optional.map(new d(aVar, 0)).orElse(Integer.valueOf(SubsamplingScaleImageView.TILE_SIZE_AUTO));
        int iIntValue = num.intValue();
        for (int i2 = 0; i2 < iD; i2++) {
            int i3 = iA + 1;
            boolean zB = aVar.b(iA);
            int iF = aVar.f(i3);
            l lVar = l.M;
            int iA2 = lVar.a(aVar) + i3;
            if (zB) {
                int iF2 = aVar.f(iA2);
                int iA3 = lVar.a(aVar) + iA2;
                if (iF > iF2) {
                    throw new InvalidRangeFieldException(String.format("start vendor id (%d) is greater than endVendorId (%d)", Integer.valueOf(iF), Integer.valueOf(iF2)));
                }
                if (iF2 > iIntValue) {
                    throw new InvalidRangeFieldException(String.format("end vendor id (%d) is greater than max (%d)", Integer.valueOf(iF2), num));
                }
                bitSet.set(iF, iF2 + 1);
                iA = iA3;
            } else {
                bitSet.set(iF);
                iA = iA2;
            }
        }
        return iA;
    }

    public static com.iabtcf.utils.c g(com.iabtcf.utils.a aVar, l lVar) {
        int iB = lVar.b(aVar);
        int iA = lVar.a(aVar);
        com.iabtcf.utils.c cVar = com.iabtcf.utils.c.b;
        BitSet bitSet = new BitSet();
        for (int i = 0; i < iA; i++) {
            if (aVar.b(iB + i)) {
                bitSet.set(i + 1);
            }
        }
        return new com.iabtcf.utils.c((BitSet) bitSet.clone());
    }

    public static com.iabtcf.utils.c h(com.iabtcf.utils.a aVar, l lVar, l lVar2) {
        BitSet bitSet = new BitSet();
        aVar.getClass();
        int iF = aVar.f(lVar.b(aVar));
        if (aVar.b(lVar.b(aVar) + lVar.a(aVar))) {
            D(aVar, bitSet, lVar2.b(aVar), Optional.of(lVar));
        } else {
            for (int i = 0; i < iF; i++) {
                if (aVar.b(lVar2.b(aVar) + i)) {
                    bitSet.set(i + 1);
                }
            }
        }
        return new com.iabtcf.utils.c((BitSet) bitSet.clone());
    }

    public final boolean A() {
        l lVar = l.o;
        if (this.z.add(lVar)) {
            this.k = this.A.c(lVar);
        }
        return this.k;
    }

    public final n B() {
        l lVar = l.x;
        if (this.z.add(lVar)) {
            this.r = h(this.A, l.w, lVar);
        }
        return this.r;
    }

    public final boolean C() {
        l lVar = l.n;
        if (this.z.add(lVar)) {
            this.j = this.A.c(lVar);
        }
        return this.j;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0043  */
    @Override // com.iabtcf.decoder.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List a() {
        /*
            r10 = this;
            java.util.EnumSet r0 = r10.z
            com.iabtcf.utils.l r1 = com.iabtcf.utils.l.z
            boolean r0 = r0.add(r1)
            if (r0 == 0) goto L6c
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            r10.s = r0
            com.iabtcf.utils.l r1 = com.iabtcf.utils.l.y
            com.iabtcf.utils.a r2 = r10.A
            int r1 = r1.b(r2)
            int r3 = r2.d(r1)
            com.iabtcf.utils.l r4 = com.iabtcf.utils.l.K
            int r4 = r4.a(r2)
            int r4 = r4 + r1
            r1 = 0
        L25:
            if (r1 >= r3) goto L6c
            byte r5 = r2.h(r4)
            com.iabtcf.utils.l r6 = com.iabtcf.utils.l.W
            int r6 = r6.a(r2)
            int r6 = r6 + r4
            r4 = 2
            byte r7 = r2.j(r6, r4)
            int r6 = r6 + 2
            r8 = 1
            if (r7 == 0) goto L43
            if (r7 == r8) goto L48
            r9 = 3
            if (r7 == r4) goto L47
            if (r7 == r9) goto L45
        L43:
            r4 = r8
            goto L48
        L45:
            r4 = 4
            goto L48
        L47:
            r4 = r9
        L48:
            java.util.BitSet r7 = new java.util.BitSet
            r7.<init>()
            java.util.Optional r8 = java.util.Optional.empty()
            int r6 = D(r2, r7, r6, r8)
            com.iabtcf.v2.a r8 = new com.iabtcf.v2.a
            com.iabtcf.utils.c r9 = new com.iabtcf.utils.c
            java.lang.Object r7 = r7.clone()
            java.util.BitSet r7 = (java.util.BitSet) r7
            r9.<init>(r7)
            r8.<init>(r5, r4, r9)
            r0.add(r8)
            int r1 = r1 + 1
            r4 = r6
            goto L25
        L6c:
            java.util.ArrayList r0 = r10.s
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.iabtcf.decoder.e.a():java.util.List");
    }

    @Override // com.iabtcf.decoder.b
    public final n b() {
        l lVar = l.q;
        if (this.z.add(lVar)) {
            this.m = g(this.A, lVar);
        }
        return this.m;
    }

    @Override // com.iabtcf.decoder.b
    public final n c() {
        l lVar = l.v;
        if (this.z.add(lVar)) {
            this.q = h(this.A, l.u, lVar);
        }
        return this.q;
    }

    @Override // com.iabtcf.decoder.b
    public final int e() {
        l lVar = l.l;
        if (this.z.add(lVar)) {
            this.h = (short) this.A.e(lVar);
        }
        return this.h;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || e.class != obj.getClass()) {
            return false;
        }
        e eVar = (e) obj;
        return Objects.equals(i(), eVar.i()) && Objects.equals(l(), eVar.l()) && j() == eVar.j() && k() == eVar.k() && Objects.equals(n(), eVar.n()) && Objects.equals(r(), eVar.r()) && m() == eVar.m() && Objects.equals(o(), eVar.o()) && Objects.equals(p(), eVar.p()) && Objects.equals(q(), eVar.q()) && v() == eVar.v() && C() == eVar.C() && z() == eVar.z() && Objects.equals(u(), eVar.u()) && Objects.equals(s(), eVar.s()) && Objects.equals(t(), eVar.t()) && Objects.equals(a(), eVar.a()) && Objects.equals(b(), eVar.b()) && Objects.equals(w(), eVar.w()) && Objects.equals(y(), eVar.y()) && A() == eVar.A() && Objects.equals(c(), eVar.c()) && Objects.equals(B(), eVar.B()) && e() == eVar.e() && f() == eVar.f();
    }

    @Override // com.iabtcf.decoder.b
    public final int f() {
        l lVar = l.e;
        if (this.z.add(lVar)) {
            this.a = this.A.i(lVar);
        }
        return this.a;
    }

    public final int hashCode() {
        return Objects.hash(i(), l(), Integer.valueOf(j()), Integer.valueOf(k()), n(), r(), Integer.valueOf(m()), o(), p(), q(), Boolean.valueOf(v()), Boolean.valueOf(C()), Integer.valueOf(z()), u(), s(), t(), a(), b(), w(), y(), Boolean.valueOf(A()), c(), B(), Integer.valueOf(e()), Integer.valueOf(f()));
    }

    public final n i() {
        l lVar = l.E;
        if (this.z.add(lVar)) {
            this.u = com.iabtcf.utils.c.b;
            com.iabtcf.utils.a aVarX = x(3);
            if (aVarX != null) {
                this.u = h(aVarX, l.D, lVar);
            }
        }
        return this.u;
    }

    public final int j() {
        l lVar = l.h;
        if (this.z.add(lVar)) {
            this.d = (short) this.A.e(lVar);
        }
        return this.d;
    }

    public final int k() {
        l lVar = l.i;
        if (this.z.add(lVar)) {
            this.e = (short) this.A.e(lVar);
        }
        return this.e;
    }

    public final String l() {
        l lVar = l.k;
        if (this.z.add(lVar)) {
            this.g = this.A.k(lVar);
        }
        return this.g;
    }

    public final int m() {
        l lVar = l.j;
        if (this.z.add(lVar)) {
            this.f = this.A.i(lVar);
        }
        return this.f;
    }

    public final Instant n() {
        l lVar = l.f;
        if (this.z.add(lVar)) {
            this.b = Instant.ofEpochMilli(this.A.g(lVar) * 100);
        }
        return this.b;
    }

    public final n o() {
        l lVar = l.I;
        if (this.z.add(lVar)) {
            this.x = com.iabtcf.utils.c.b;
            com.iabtcf.utils.a aVarX = x(4);
            if (aVarX != null) {
                this.x = g(aVarX, lVar);
            }
        }
        return this.x;
    }

    public final n p() {
        l lVar = l.J;
        if (this.z.add(lVar)) {
            this.y = com.iabtcf.utils.c.b;
            com.iabtcf.utils.a aVarX = x(4);
            if (aVarX != null) {
                this.y = g(aVarX, lVar);
            }
        }
        return this.y;
    }

    public final n q() {
        l lVar = l.C;
        if (this.z.add(lVar)) {
            this.t = com.iabtcf.utils.c.b;
            com.iabtcf.utils.a aVarX = x(2);
            if (aVarX != null) {
                this.t = h(aVarX, l.B, lVar);
            }
        }
        return this.t;
    }

    public final Instant r() {
        l lVar = l.g;
        if (this.z.add(lVar)) {
            this.c = Instant.ofEpochMilli(this.A.g(lVar) * 100);
        }
        return this.c;
    }

    public final n s() {
        l lVar = l.F;
        if (this.z.add(lVar)) {
            this.v = com.iabtcf.utils.c.b;
            com.iabtcf.utils.a aVarX = x(4);
            if (aVarX != null) {
                this.v = g(aVarX, lVar);
            }
        }
        return this.v;
    }

    public final n t() {
        l lVar = l.G;
        if (this.z.add(lVar)) {
            this.w = com.iabtcf.utils.c.b;
            com.iabtcf.utils.a aVarX = x(4);
            if (aVarX != null) {
                this.w = g(aVarX, lVar);
            }
        }
        return this.w;
    }

    public final String toString() {
        return "TCStringV2 [getVersion()=" + f() + ", getCreated()=" + n() + ", getLastUpdated()=" + r() + ", getCmpId()=" + j() + ", getCmpVersion()=" + k() + ", getConsentScreen()=" + m() + ", getConsentLanguage()=" + l() + ", getVendorListVersion()=" + e() + ", getTcfPolicyVersion()=" + z() + ", isServiceSpecific()=" + C() + ", getUseNonStandardStacks()=" + A() + ", getSpecialFeatureOptIns()=" + y() + ", getPurposesConsent()=" + b() + ", getPurposesLITransparency()=" + w() + ", getPurposeOneTreatment()=" + v() + ", getPublisherCC()=" + u() + ", getVendorConsent()=" + c() + ", getVendorLegitimateInterest()=" + B() + ", getPublisherRestrictions()=" + a() + ", getDisclosedVendors()=" + q() + ", getAllowedVendors()=" + i() + ", getPubPurposesConsent()=" + s() + ", getPubPurposesLITransparency()=" + t() + ", getCustomPurposesConsent()=" + o() + ", getCustomPurposesLITransparency()=" + p() + "]";
    }

    public final String u() {
        l lVar = l.t;
        if (this.z.add(lVar)) {
            this.p = this.A.k(lVar);
        }
        return this.p;
    }

    public final boolean v() {
        l lVar = l.s;
        if (this.z.add(lVar)) {
            this.o = this.A.c(lVar);
        }
        return this.o;
    }

    public final n w() {
        l lVar = l.r;
        if (this.z.add(lVar)) {
            this.n = g(this.A, lVar);
        }
        return this.n;
    }

    public final com.iabtcf.utils.a x(int i) {
        if (i == 1) {
            return this.A;
        }
        for (com.iabtcf.utils.a aVar : this.B) {
            l lVar = l.A;
            aVar.getClass();
            int i2 = 3;
            byte bJ = aVar.j(lVar.b(aVar), 3);
            if (bJ == 0) {
                i2 = 1;
            } else if (bJ == 1) {
                i2 = 2;
            } else if (bJ != 2) {
                i2 = bJ != 3 ? 5 : 4;
            }
            if (i == i2) {
                return aVar;
            }
        }
        return null;
    }

    public final n y() {
        l lVar = l.p;
        if (this.z.add(lVar)) {
            this.l = g(this.A, lVar);
        }
        return this.l;
    }

    public final int z() {
        l lVar = l.m;
        if (this.z.add(lVar)) {
            this.i = this.A.i(lVar);
        }
        return this.i;
    }
}
