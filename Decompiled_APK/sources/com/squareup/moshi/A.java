package com.squareup.moshi;

import androidx.compose.runtime.changelist.K;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Set;

/* loaded from: classes3.dex */
public final class A extends AbstractMap implements Serializable {
    public static final com.google.zxing.aztec.encoder.c i = new com.google.zxing.aztec.encoder.c(24);
    public y g;
    public y h;
    public int d = 0;
    public int e = 0;
    public final Comparator a = i;
    public final z c = new z();
    public z[] b = new z[16];
    public int f = 12;

    private Object writeReplace() throws ObjectStreamException {
        return new LinkedHashMap(this);
    }

    public final z a(Object obj, boolean z) {
        int iCompareTo;
        z zVar;
        boolean z2;
        z zVar2;
        z zVar3;
        z zVar4;
        z zVar5;
        z zVar6;
        z[] zVarArr = this.b;
        int iHashCode = obj.hashCode();
        int i2 = iHashCode ^ ((iHashCode >>> 20) ^ (iHashCode >>> 12));
        int i3 = ((i2 >>> 7) ^ i2) ^ (i2 >>> 4);
        boolean z3 = true;
        int length = i3 & (zVarArr.length - 1);
        z zVar7 = zVarArr[length];
        com.google.zxing.aztec.encoder.c cVar = i;
        z zVar8 = null;
        Comparator comparator = this.a;
        if (zVar7 != null) {
            Comparable comparable = comparator == cVar ? (Comparable) obj : null;
            while (true) {
                Object obj2 = zVar7.f;
                iCompareTo = comparable != null ? comparable.compareTo(obj2) : comparator.compare(obj, obj2);
                if (iCompareTo == 0) {
                    return zVar7;
                }
                z zVar9 = iCompareTo < 0 ? zVar7.b : zVar7.c;
                if (zVar9 == null) {
                    break;
                }
                zVar7 = zVar9;
            }
        } else {
            iCompareTo = 0;
        }
        if (!z) {
            return null;
        }
        z zVar10 = this.c;
        if (zVar7 != null) {
            z zVar11 = zVar7;
            zVar = new z(zVar11, obj, i3, zVar10, zVar10.e);
            if (iCompareTo < 0) {
                zVar11.b = zVar;
            } else {
                zVar11.c = zVar;
            }
            b(zVar11, true);
        } else {
            if (comparator == cVar && !(obj instanceof Comparable)) {
                throw new ClassCastException(obj.getClass().getName().concat(" is not Comparable"));
            }
            zVar = new z(zVar7, obj, i3, zVar10, zVar10.e);
            zVarArr[length] = zVar;
        }
        int i4 = this.d;
        this.d = i4 + 1;
        if (i4 > this.f) {
            z[] zVarArr2 = this.b;
            int length2 = zVarArr2.length;
            int i5 = length2 * 2;
            z[] zVarArr3 = new z[i5];
            K k = new K(4, (byte) 0);
            K k2 = new K(4, (byte) 0);
            int i6 = 0;
            while (i6 < length2) {
                z zVar12 = zVarArr2[i6];
                if (zVar12 == null) {
                    z2 = z3;
                    zVar3 = zVar8;
                } else {
                    z zVar13 = zVar8;
                    for (z zVar14 = zVar12; zVar14 != null; zVar14 = zVar14.b) {
                        zVar14.a = zVar13;
                        zVar13 = zVar14;
                    }
                    int i7 = 0;
                    int i8 = 0;
                    while (true) {
                        if (zVar13 != null) {
                            z2 = z3;
                            z zVar15 = zVar13.a;
                            zVar13.a = zVar8;
                            z zVar16 = zVar13.c;
                            while (true) {
                                z zVar17 = zVar16;
                                zVar2 = zVar15;
                                zVar15 = zVar17;
                                if (zVar15 == null) {
                                    break;
                                }
                                zVar15.a = zVar2;
                                zVar16 = zVar15.b;
                            }
                        } else {
                            z zVar18 = zVar13;
                            zVar13 = zVar8;
                            zVar2 = zVar18;
                            z2 = z3;
                        }
                        if (zVar13 == null) {
                            break;
                        }
                        if ((zVar13.g & length2) == 0) {
                            i7++;
                        } else {
                            i8++;
                        }
                        zVar13 = zVar2;
                        z3 = z2;
                        zVar8 = null;
                    }
                    k.b = ((Integer.highestOneBit(i7) * 2) - 1) - i7;
                    k.d = 0;
                    k.c = 0;
                    zVar3 = null;
                    k.e = null;
                    k2.b = ((Integer.highestOneBit(i8) * 2) - 1) - i8;
                    k2.d = 0;
                    k2.c = 0;
                    k2.e = null;
                    z zVar19 = null;
                    while (zVar12 != null) {
                        zVar12.a = zVar19;
                        z zVar20 = zVar12;
                        zVar12 = zVar12.b;
                        zVar19 = zVar20;
                    }
                    while (true) {
                        if (zVar19 != null) {
                            z zVar21 = zVar19.a;
                            zVar19.a = null;
                            z zVar22 = zVar19.c;
                            while (true) {
                                z zVar23 = zVar22;
                                zVar4 = zVar21;
                                zVar21 = zVar23;
                                if (zVar21 == null) {
                                    break;
                                }
                                zVar21.a = zVar4;
                                zVar22 = zVar21.b;
                            }
                        } else {
                            zVar4 = zVar19;
                            zVar19 = null;
                        }
                        if (zVar19 == null) {
                            break;
                        }
                        if ((zVar19.g & length2) == 0) {
                            k.a(zVar19);
                        } else {
                            k2.a(zVar19);
                        }
                        zVar19 = zVar4;
                    }
                    if (i7 > 0) {
                        zVar5 = (z) k.e;
                        if (zVar5.a != null) {
                            throw new IllegalStateException();
                        }
                    } else {
                        zVar5 = null;
                    }
                    zVarArr3[i6] = zVar5;
                    int i9 = i6 + length2;
                    if (i8 > 0) {
                        zVar6 = (z) k2.e;
                        if (zVar6.a != null) {
                            throw new IllegalStateException();
                        }
                    } else {
                        zVar6 = null;
                    }
                    zVarArr3[i9] = zVar6;
                }
                i6++;
                zVar8 = zVar3;
                z3 = z2;
            }
            this.b = zVarArr3;
            this.f = (i5 / 4) + (i5 / 2);
        }
        this.e++;
        return zVar;
    }

    public final void b(z zVar, boolean z) {
        while (zVar != null) {
            z zVar2 = zVar.b;
            z zVar3 = zVar.c;
            int i2 = zVar2 != null ? zVar2.i : 0;
            int i3 = zVar3 != null ? zVar3.i : 0;
            int i4 = i2 - i3;
            if (i4 == -2) {
                z zVar4 = zVar3.b;
                z zVar5 = zVar3.c;
                int i5 = (zVar4 != null ? zVar4.i : 0) - (zVar5 != null ? zVar5.i : 0);
                if (i5 != -1 && (i5 != 0 || z)) {
                    g(zVar3);
                }
                f(zVar);
                if (z) {
                    return;
                }
            } else if (i4 == 2) {
                z zVar6 = zVar2.b;
                z zVar7 = zVar2.c;
                int i6 = (zVar6 != null ? zVar6.i : 0) - (zVar7 != null ? zVar7.i : 0);
                if (i6 != 1 && (i6 != 0 || z)) {
                    f(zVar2);
                }
                g(zVar);
                if (z) {
                    return;
                }
            } else if (i4 == 0) {
                zVar.i = i2 + 1;
                if (z) {
                    return;
                }
            } else {
                zVar.i = Math.max(i2, i3) + 1;
                if (!z) {
                    return;
                }
            }
            zVar = zVar.a;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        Arrays.fill(this.b, (Object) null);
        this.d = 0;
        this.e++;
        z zVar = this.c;
        z zVar2 = zVar.d;
        while (zVar2 != zVar) {
            z zVar3 = zVar2.d;
            zVar2.e = null;
            zVar2.d = null;
            zVar2 = zVar3;
        }
        zVar.e = zVar;
        zVar.d = zVar;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        z zVarA = null;
        if (obj != null) {
            try {
                zVarA = a(obj, false);
            } catch (ClassCastException unused) {
            }
        }
        return zVarA != null;
    }

    public final void d(z zVar, boolean z) {
        z zVar2;
        z zVar3;
        int i2;
        if (z) {
            z zVar4 = zVar.e;
            zVar4.d = zVar.d;
            zVar.d.e = zVar4;
            zVar.e = null;
            zVar.d = null;
        }
        z zVar5 = zVar.b;
        z zVar6 = zVar.c;
        z zVar7 = zVar.a;
        int i3 = 0;
        if (zVar5 == null || zVar6 == null) {
            if (zVar5 != null) {
                e(zVar, zVar5);
                zVar.b = null;
            } else if (zVar6 != null) {
                e(zVar, zVar6);
                zVar.c = null;
            } else {
                e(zVar, null);
            }
            b(zVar7, false);
            this.d--;
            this.e++;
            return;
        }
        if (zVar5.i > zVar6.i) {
            z zVar8 = zVar5.c;
            while (true) {
                z zVar9 = zVar8;
                zVar3 = zVar5;
                zVar5 = zVar9;
                if (zVar5 == null) {
                    break;
                } else {
                    zVar8 = zVar5.c;
                }
            }
        } else {
            z zVar10 = zVar6.b;
            while (true) {
                zVar2 = zVar6;
                zVar6 = zVar10;
                if (zVar6 == null) {
                    break;
                } else {
                    zVar10 = zVar6.b;
                }
            }
            zVar3 = zVar2;
        }
        d(zVar3, false);
        z zVar11 = zVar.b;
        if (zVar11 != null) {
            i2 = zVar11.i;
            zVar3.b = zVar11;
            zVar11.a = zVar3;
            zVar.b = null;
        } else {
            i2 = 0;
        }
        z zVar12 = zVar.c;
        if (zVar12 != null) {
            i3 = zVar12.i;
            zVar3.c = zVar12;
            zVar12.a = zVar3;
            zVar.c = null;
        }
        zVar3.i = Math.max(i2, i3) + 1;
        e(zVar, zVar3);
    }

    public final void e(z zVar, z zVar2) {
        z zVar3 = zVar.a;
        zVar.a = null;
        if (zVar2 != null) {
            zVar2.a = zVar3;
        }
        if (zVar3 == null) {
            this.b[zVar.g & (r0.length - 1)] = zVar2;
        } else if (zVar3.b == zVar) {
            zVar3.b = zVar2;
        } else {
            zVar3.c = zVar2;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set entrySet() {
        y yVar = this.g;
        if (yVar != null) {
            return yVar;
        }
        y yVar2 = new y(this, 0);
        this.g = yVar2;
        return yVar2;
    }

    public final void f(z zVar) {
        z zVar2 = zVar.b;
        z zVar3 = zVar.c;
        z zVar4 = zVar3.b;
        z zVar5 = zVar3.c;
        zVar.c = zVar4;
        if (zVar4 != null) {
            zVar4.a = zVar;
        }
        e(zVar, zVar3);
        zVar3.b = zVar;
        zVar.a = zVar3;
        int iMax = Math.max(zVar2 != null ? zVar2.i : 0, zVar4 != null ? zVar4.i : 0) + 1;
        zVar.i = iMax;
        zVar3.i = Math.max(iMax, zVar5 != null ? zVar5.i : 0) + 1;
    }

    public final void g(z zVar) {
        z zVar2 = zVar.b;
        z zVar3 = zVar.c;
        z zVar4 = zVar2.b;
        z zVar5 = zVar2.c;
        zVar.b = zVar5;
        if (zVar5 != null) {
            zVar5.a = zVar;
        }
        e(zVar, zVar2);
        zVar2.c = zVar;
        zVar.a = zVar2;
        int iMax = Math.max(zVar3 != null ? zVar3.i : 0, zVar5 != null ? zVar5.i : 0) + 1;
        zVar.i = iMax;
        zVar2.i = Math.max(iMax, zVar4 != null ? zVar4.i : 0) + 1;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        z zVarA;
        if (obj != null) {
            try {
                zVarA = a(obj, false);
            } catch (ClassCastException unused) {
            }
        } else {
            zVarA = null;
        }
        if (zVarA != null) {
            return zVarA.h;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set keySet() {
        y yVar = this.h;
        if (yVar != null) {
            return yVar;
        }
        y yVar2 = new y(this, 1);
        this.h = yVar2;
        return yVar2;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        if (obj == null) {
            throw new NullPointerException("key == null");
        }
        z zVarA = a(obj, true);
        Object obj3 = zVarA.h;
        zVarA.h = obj2;
        return obj3;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object remove(Object obj) {
        z zVarA;
        if (obj != null) {
            try {
                zVarA = a(obj, false);
            } catch (ClassCastException unused) {
            }
        } else {
            zVarA = null;
        }
        if (zVarA != null) {
            d(zVarA, true);
        }
        if (zVarA != null) {
            return zVarA.h;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int size() {
        return this.d;
    }
}
