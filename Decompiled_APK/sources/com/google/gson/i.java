package com.google.gson;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

/* loaded from: classes2.dex */
public final class i extends q {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;

    public /* synthetic */ i(q qVar, int i) {
        this.a = i;
        this.b = qVar;
    }

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) {
        switch (this.a) {
            case 0:
                return new AtomicLong(((Number) this.b.a(aVar)).longValue());
            case 1:
                ArrayList arrayList = new ArrayList();
                aVar.a();
                while (aVar.q()) {
                    arrayList.add(Long.valueOf(((Number) this.b.a(aVar)).longValue()));
                }
                aVar.j();
                int size = arrayList.size();
                AtomicLongArray atomicLongArray = new AtomicLongArray(size);
                for (int i = 0; i < size; i++) {
                    atomicLongArray.set(i, ((Long) arrayList.get(i)).longValue());
                }
                return atomicLongArray;
            default:
                if (aVar.l0() != 9) {
                    return this.b.a(aVar);
                }
                aVar.a0();
                return null;
        }
    }
}
