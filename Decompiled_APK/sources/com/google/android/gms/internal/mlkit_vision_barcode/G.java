package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.mlkit_vision_document_scanner.C3620g;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3628h;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3636i;
import java.io.Serializable;
import java.util.AbstractCollection;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class G implements Map, Serializable {
    public final /* synthetic */ int a;
    public final transient Object[] b;
    public transient AbstractCollection c;
    public transient AbstractCollection d;
    public transient AbstractCollection e;

    public /* synthetic */ G(Object[] objArr, int i) {
        this.a = i;
        this.b = objArr;
    }

    @Override // java.util.Map
    public final void clear() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        switch (this.a) {
            case 0:
                if (get(obj) != null) {
                }
                break;
            case 1:
                if (get(obj) != null) {
                }
                break;
            default:
                if (get(obj) != null) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        switch (this.a) {
            case 0:
                F f = (F) this.e;
                if (f == null) {
                    f = new F(this.b, 1);
                    this.e = f;
                }
                return f.contains(obj);
            case 1:
                com.google.android.gms.internal.mlkit_vision_common.X4 x4 = (com.google.android.gms.internal.mlkit_vision_common.X4) this.e;
                if (x4 == null) {
                    x4 = new com.google.android.gms.internal.mlkit_vision_common.X4(this.b, 1);
                    this.e = x4;
                }
                return x4.contains(obj);
            default:
                C3636i c3636i = (C3636i) this.e;
                if (c3636i == null) {
                    c3636i = new C3636i(this.b, 1);
                    this.e = c3636i;
                }
                return c3636i.contains(obj);
        }
    }

    @Override // java.util.Map
    public final Set entrySet() {
        switch (this.a) {
            case 0:
                D d = (D) this.c;
                if (d != null) {
                    return d;
                }
                D d2 = new D(this, this.b);
                this.c = d2;
                return d2;
            case 1:
                com.google.android.gms.internal.mlkit_vision_common.V4 v4 = (com.google.android.gms.internal.mlkit_vision_common.V4) this.c;
                if (v4 != null) {
                    return v4;
                }
                com.google.android.gms.internal.mlkit_vision_common.V4 v42 = new com.google.android.gms.internal.mlkit_vision_common.V4(this, this.b);
                this.c = v42;
                return v42;
            default:
                C3620g c3620g = (C3620g) this.c;
                if (c3620g != null) {
                    return c3620g;
                }
                C3620g c3620g2 = new C3620g(this, this.b);
                this.c = c3620g2;
                return c3620g2;
        }
    }

    @Override // java.util.Map
    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if (this != obj) {
                    if (obj instanceof Map) {
                        break;
                    }
                }
                break;
            case 1:
                if (this != obj) {
                    if (obj instanceof Map) {
                        break;
                    }
                }
                break;
            default:
                if (this != obj) {
                    if (obj instanceof Map) {
                        break;
                    }
                }
                break;
        }
        return entrySet().equals(((Map) obj).entrySet());
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0008  */
    @Override // java.util.Map
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object get(java.lang.Object r4) {
        /*
            r3 = this;
            int r0 = r3.a
            switch(r0) {
                case 0: goto L41;
                case 1: goto L23;
                default: goto L5;
            }
        L5:
            r0 = 0
            if (r4 != 0) goto La
        L8:
            r4 = r0
            goto L1e
        La:
            java.lang.Object[] r1 = r3.b
            r2 = 0
            r2 = r1[r2]
            java.util.Objects.requireNonNull(r2)
            boolean r4 = r2.equals(r4)
            if (r4 == 0) goto L8
            r4 = 1
            r4 = r1[r4]
            java.util.Objects.requireNonNull(r4)
        L1e:
            if (r4 != 0) goto L21
            goto L22
        L21:
            r0 = r4
        L22:
            return r0
        L23:
            r0 = 0
            if (r4 != 0) goto L28
        L26:
            r4 = r0
            goto L3c
        L28:
            java.lang.Object[] r1 = r3.b
            r2 = 0
            r2 = r1[r2]
            r2.getClass()
            boolean r4 = r2.equals(r4)
            if (r4 == 0) goto L26
            r4 = 1
            r4 = r1[r4]
            r4.getClass()
        L3c:
            if (r4 != 0) goto L3f
            goto L40
        L3f:
            r0 = r4
        L40:
            return r0
        L41:
            r0 = 0
            if (r4 != 0) goto L46
        L44:
            r4 = r0
            goto L5a
        L46:
            r1 = 0
            java.lang.Object[] r2 = r3.b
            r1 = r2[r1]
            java.util.Objects.requireNonNull(r1)
            boolean r4 = r1.equals(r4)
            if (r4 == 0) goto L44
            r4 = 1
            r4 = r2[r4]
            java.util.Objects.requireNonNull(r4)
        L5a:
            if (r4 != 0) goto L5d
            goto L5e
        L5d:
            r0 = r4
        L5e:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.G.get(java.lang.Object):java.lang.Object");
    }

    @Override // java.util.Map
    public final Object getOrDefault(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Object obj3 = get(obj);
                return obj3 != null ? obj3 : obj2;
            case 1:
                Object obj4 = get(obj);
                return obj4 != null ? obj4 : obj2;
            default:
                Object obj5 = get(obj);
                return obj5 != null ? obj5 : obj2;
        }
    }

    @Override // java.util.Map
    public final int hashCode() {
        switch (this.a) {
            case 0:
                D d = (D) this.c;
                if (d == null) {
                    d = new D(this, this.b);
                    this.c = d;
                }
                Iterator it2 = d.iterator();
                int iHashCode = 0;
                while (it2.hasNext()) {
                    Object next = it2.next();
                    iHashCode += next != null ? next.hashCode() : 0;
                }
                return iHashCode;
            case 1:
                com.google.android.gms.internal.mlkit_vision_common.V4 v4 = (com.google.android.gms.internal.mlkit_vision_common.V4) this.c;
                if (v4 == null) {
                    v4 = new com.google.android.gms.internal.mlkit_vision_common.V4(this, this.b);
                    this.c = v4;
                }
                Iterator it3 = v4.iterator();
                int iHashCode2 = 0;
                while (it3.hasNext()) {
                    Object next2 = it3.next();
                    iHashCode2 += next2 != null ? next2.hashCode() : 0;
                }
                return iHashCode2;
            default:
                C3620g c3620g = (C3620g) this.c;
                if (c3620g == null) {
                    c3620g = new C3620g(this, this.b);
                    this.c = c3620g;
                }
                Iterator it4 = c3620g.iterator();
                int iHashCode3 = 0;
                while (it4.hasNext()) {
                    Object next3 = it4.next();
                    iHashCode3 += next3 != null ? next3.hashCode() : 0;
                }
                return iHashCode3;
        }
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        switch (this.a) {
        }
        return false;
    }

    @Override // java.util.Map
    public final Set keySet() {
        switch (this.a) {
            case 0:
                E e = (E) this.d;
                if (e != null) {
                    return e;
                }
                E e2 = new E(this, new F(this.b, 0));
                this.d = e2;
                return e2;
            case 1:
                com.google.android.gms.internal.mlkit_vision_common.W4 w4 = (com.google.android.gms.internal.mlkit_vision_common.W4) this.d;
                if (w4 != null) {
                    return w4;
                }
                com.google.android.gms.internal.mlkit_vision_common.W4 w42 = new com.google.android.gms.internal.mlkit_vision_common.W4(this, new com.google.android.gms.internal.mlkit_vision_common.X4(this.b, 0));
                this.d = w42;
                return w42;
            default:
                C3628h c3628h = (C3628h) this.d;
                if (c3628h != null) {
                    return c3628h;
                }
                C3628h c3628h2 = new C3628h(this, new C3636i(this.b, 0));
                this.d = c3628h2;
                return c3628h2;
        }
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.Map
    public final int size() {
        switch (this.a) {
        }
        return 1;
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                boolean z = true;
                StringBuilder sb = new StringBuilder((int) Math.min(1 * 8, 1073741824L));
                sb.append('{');
                Iterator it2 = ((D) entrySet()).iterator();
                while (it2.hasNext()) {
                    Map.Entry entry = (Map.Entry) it2.next();
                    if (!z) {
                        sb.append(", ");
                    }
                    sb.append(entry.getKey());
                    sb.append('=');
                    sb.append(entry.getValue());
                    z = false;
                }
                sb.append('}');
                return sb.toString();
            case 1:
                boolean z2 = true;
                StringBuilder sb2 = new StringBuilder((int) Math.min(1 * 8, 1073741824L));
                sb2.append('{');
                Iterator it3 = ((com.google.android.gms.internal.mlkit_vision_common.V4) entrySet()).iterator();
                while (it3.hasNext()) {
                    Map.Entry entry2 = (Map.Entry) it3.next();
                    if (!z2) {
                        sb2.append(", ");
                    }
                    sb2.append(entry2.getKey());
                    sb2.append('=');
                    sb2.append(entry2.getValue());
                    z2 = false;
                }
                sb2.append('}');
                return sb2.toString();
            default:
                boolean z3 = true;
                StringBuilder sb3 = new StringBuilder((int) Math.min(1 * 8, 1073741824L));
                sb3.append('{');
                Iterator it4 = ((C3620g) entrySet()).iterator();
                while (it4.hasNext()) {
                    Map.Entry entry3 = (Map.Entry) it4.next();
                    if (!z3) {
                        sb3.append(", ");
                    }
                    sb3.append(entry3.getKey());
                    sb3.append('=');
                    sb3.append(entry3.getValue());
                    z3 = false;
                }
                sb3.append('}');
                return sb3.toString();
        }
    }

    @Override // java.util.Map
    public final Collection values() {
        switch (this.a) {
            case 0:
                F f = (F) this.e;
                if (f != null) {
                    return f;
                }
                F f2 = new F(this.b, 1);
                this.e = f2;
                return f2;
            case 1:
                com.google.android.gms.internal.mlkit_vision_common.X4 x4 = (com.google.android.gms.internal.mlkit_vision_common.X4) this.e;
                if (x4 != null) {
                    return x4;
                }
                com.google.android.gms.internal.mlkit_vision_common.X4 x42 = new com.google.android.gms.internal.mlkit_vision_common.X4(this.b, 1);
                this.e = x42;
                return x42;
            default:
                C3636i c3636i = (C3636i) this.e;
                if (c3636i != null) {
                    return c3636i;
                }
                C3636i c3636i2 = new C3636i(this.b, 1);
                this.e = c3636i2;
                return c3636i2;
        }
    }
}
