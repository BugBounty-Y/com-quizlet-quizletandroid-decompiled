package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.measurement.internal.zzbf;
import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3308z implements Iterator {
    public final /* synthetic */ int a = 1;
    public final Iterator b;

    public C3308z(zzbf zzbfVar) {
        this.b = zzbfVar.a.keySet().iterator();
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
        }
        return this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                return ((Map.Entry) this.b.next()).getValue();
            default:
                return (String) this.b.next();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                this.b.remove();
                return;
            default:
                throw new UnsupportedOperationException("Remove not supported");
        }
    }

    public C3308z(Iterator it2) {
        it2.getClass();
        this.b = it2;
    }
}
