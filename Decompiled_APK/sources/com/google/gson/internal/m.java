package com.google.gson.internal;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.util.AbstractMap;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Set;

/* loaded from: classes2.dex */
public final class m extends AbstractMap implements Serializable {
    public static final androidx.constraintlayout.core.e h = new androidx.constraintlayout.core.e(29);
    public final Comparator a;
    public l b;
    public int c;
    public int d;
    public final l e;
    public j f;
    public j g;

    public m() {
        androidx.constraintlayout.core.e eVar = h;
        this.c = 0;
        this.d = 0;
        this.e = new l();
        this.a = eVar;
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException {
        throw new InvalidObjectException("Deserialization is unsupported");
    }

    private Object writeReplace() throws ObjectStreamException {
        return new LinkedHashMap(this);
    }

    public final l a(Object obj, boolean z) {
        int iCompareTo;
        l lVar;
        l lVar2 = this.b;
        androidx.constraintlayout.core.e eVar = h;
        Comparator comparator = this.a;
        if (lVar2 != null) {
            Comparable comparable = comparator == eVar ? (Comparable) obj : null;
            while (true) {
                Object obj2 = lVar2.f;
                iCompareTo = comparable != null ? comparable.compareTo(obj2) : comparator.compare(obj, obj2);
                if (iCompareTo == 0) {
                    return lVar2;
                }
                l lVar3 = iCompareTo < 0 ? lVar2.b : lVar2.c;
                if (lVar3 == null) {
                    break;
                }
                lVar2 = lVar3;
            }
        } else {
            iCompareTo = 0;
        }
        if (!z) {
            return null;
        }
        l lVar4 = this.e;
        if (lVar2 != null) {
            lVar = new l(lVar2, obj, lVar4, lVar4.e);
            if (iCompareTo < 0) {
                lVar2.b = lVar;
            } else {
                lVar2.c = lVar;
            }
            b(lVar2, true);
        } else {
            if (comparator == eVar && !(obj instanceof Comparable)) {
                throw new ClassCastException(obj.getClass().getName().concat(" is not Comparable"));
            }
            lVar = new l(lVar2, obj, lVar4, lVar4.e);
            this.b = lVar;
        }
        this.c++;
        this.d++;
        return lVar;
    }

    public final void b(l lVar, boolean z) {
        while (lVar != null) {
            l lVar2 = lVar.b;
            l lVar3 = lVar.c;
            int i = lVar2 != null ? lVar2.h : 0;
            int i2 = lVar3 != null ? lVar3.h : 0;
            int i3 = i - i2;
            if (i3 == -2) {
                l lVar4 = lVar3.b;
                l lVar5 = lVar3.c;
                int i4 = (lVar4 != null ? lVar4.h : 0) - (lVar5 != null ? lVar5.h : 0);
                if (i4 == -1 || (i4 == 0 && !z)) {
                    f(lVar);
                } else {
                    g(lVar3);
                    f(lVar);
                }
                if (z) {
                    return;
                }
            } else if (i3 == 2) {
                l lVar6 = lVar2.b;
                l lVar7 = lVar2.c;
                int i5 = (lVar6 != null ? lVar6.h : 0) - (lVar7 != null ? lVar7.h : 0);
                if (i5 == 1 || (i5 == 0 && !z)) {
                    g(lVar);
                } else {
                    f(lVar2);
                    g(lVar);
                }
                if (z) {
                    return;
                }
            } else if (i3 == 0) {
                lVar.h = i + 1;
                if (z) {
                    return;
                }
            } else {
                lVar.h = Math.max(i, i2) + 1;
                if (!z) {
                    return;
                }
            }
            lVar = lVar.a;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        this.b = null;
        this.c = 0;
        this.d++;
        l lVar = this.e;
        lVar.e = lVar;
        lVar.d = lVar;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        l lVarA = null;
        if (obj != null) {
            try {
                lVarA = a(obj, false);
            } catch (ClassCastException unused) {
            }
        }
        return lVarA != null;
    }

    public final void d(l lVar, boolean z) {
        l lVar2;
        l lVar3;
        int i;
        if (z) {
            l lVar4 = lVar.e;
            lVar4.d = lVar.d;
            lVar.d.e = lVar4;
        }
        l lVar5 = lVar.b;
        l lVar6 = lVar.c;
        l lVar7 = lVar.a;
        int i2 = 0;
        if (lVar5 == null || lVar6 == null) {
            if (lVar5 != null) {
                e(lVar, lVar5);
                lVar.b = null;
            } else if (lVar6 != null) {
                e(lVar, lVar6);
                lVar.c = null;
            } else {
                e(lVar, null);
            }
            b(lVar7, false);
            this.c--;
            this.d++;
            return;
        }
        if (lVar5.h > lVar6.h) {
            l lVar8 = lVar5.c;
            while (true) {
                l lVar9 = lVar8;
                lVar3 = lVar5;
                lVar5 = lVar9;
                if (lVar5 == null) {
                    break;
                } else {
                    lVar8 = lVar5.c;
                }
            }
        } else {
            l lVar10 = lVar6.b;
            while (true) {
                lVar2 = lVar6;
                lVar6 = lVar10;
                if (lVar6 == null) {
                    break;
                } else {
                    lVar10 = lVar6.b;
                }
            }
            lVar3 = lVar2;
        }
        d(lVar3, false);
        l lVar11 = lVar.b;
        if (lVar11 != null) {
            i = lVar11.h;
            lVar3.b = lVar11;
            lVar11.a = lVar3;
            lVar.b = null;
        } else {
            i = 0;
        }
        l lVar12 = lVar.c;
        if (lVar12 != null) {
            i2 = lVar12.h;
            lVar3.c = lVar12;
            lVar12.a = lVar3;
            lVar.c = null;
        }
        lVar3.h = Math.max(i, i2) + 1;
        e(lVar, lVar3);
    }

    public final void e(l lVar, l lVar2) {
        l lVar3 = lVar.a;
        lVar.a = null;
        if (lVar2 != null) {
            lVar2.a = lVar3;
        }
        if (lVar3 == null) {
            this.b = lVar2;
        } else if (lVar3.b == lVar) {
            lVar3.b = lVar2;
        } else {
            lVar3.c = lVar2;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set entrySet() {
        j jVar = this.f;
        if (jVar != null) {
            return jVar;
        }
        j jVar2 = new j(this, 0);
        this.f = jVar2;
        return jVar2;
    }

    public final void f(l lVar) {
        l lVar2 = lVar.b;
        l lVar3 = lVar.c;
        l lVar4 = lVar3.b;
        l lVar5 = lVar3.c;
        lVar.c = lVar4;
        if (lVar4 != null) {
            lVar4.a = lVar;
        }
        e(lVar, lVar3);
        lVar3.b = lVar;
        lVar.a = lVar3;
        int iMax = Math.max(lVar2 != null ? lVar2.h : 0, lVar4 != null ? lVar4.h : 0) + 1;
        lVar.h = iMax;
        lVar3.h = Math.max(iMax, lVar5 != null ? lVar5.h : 0) + 1;
    }

    public final void g(l lVar) {
        l lVar2 = lVar.b;
        l lVar3 = lVar.c;
        l lVar4 = lVar2.b;
        l lVar5 = lVar2.c;
        lVar.b = lVar5;
        if (lVar5 != null) {
            lVar5.a = lVar;
        }
        e(lVar, lVar2);
        lVar2.c = lVar;
        lVar.a = lVar2;
        int iMax = Math.max(lVar3 != null ? lVar3.h : 0, lVar5 != null ? lVar5.h : 0) + 1;
        lVar.h = iMax;
        lVar2.h = Math.max(iMax, lVar4 != null ? lVar4.h : 0) + 1;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        l lVarA;
        if (obj != null) {
            try {
                lVarA = a(obj, false);
            } catch (ClassCastException unused) {
            }
        } else {
            lVarA = null;
        }
        if (lVarA != null) {
            return lVarA.g;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set keySet() {
        j jVar = this.g;
        if (jVar != null) {
            return jVar;
        }
        j jVar2 = new j(this, 1);
        this.g = jVar2;
        return jVar2;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        if (obj == null) {
            throw new NullPointerException("key == null");
        }
        l lVarA = a(obj, true);
        Object obj3 = lVarA.g;
        lVarA.g = obj2;
        return obj3;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object remove(Object obj) {
        l lVarA;
        if (obj != null) {
            try {
                lVarA = a(obj, false);
            } catch (ClassCastException unused) {
            }
        } else {
            lVarA = null;
        }
        if (lVarA != null) {
            d(lVarA, true);
        }
        if (lVarA != null) {
            return lVarA.g;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int size() {
        return this.c;
    }
}
