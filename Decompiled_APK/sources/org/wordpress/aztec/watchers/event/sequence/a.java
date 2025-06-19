package org.wordpress.aztec.watchers.event.sequence;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.jsoup.parser.C;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public final class a extends C {
    public static final /* synthetic */ int d = 0;
    public final AztecText b;
    public final ArrayList c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(AztecText injector) {
        super(3);
        Intrinsics.checkNotNullParameter(injector, "injector");
        this.b = injector;
        ArrayList arrayList = new ArrayList();
        this.c = arrayList;
        org.wordpress.aztec.watchers.event.buckets.a aVar = new org.wordpress.aztec.watchers.event.buckets.a();
        ArrayList arrayList2 = aVar.a;
        arrayList2.add(new org.wordpress.aztec.watchers.event.sequence.known.space.a());
        org.wordpress.aztec.watchers.event.sequence.known.space.b bVar = new org.wordpress.aztec.watchers.event.sequence.known.space.b(1);
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.b bVarC = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(0).c();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1).d();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD2 = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1).d();
        bVar.a.clear();
        bVar.a(bVarC);
        bVar.a(cVarD);
        bVar.a(cVarD2);
        arrayList2.add(bVar);
        org.wordpress.aztec.watchers.event.sequence.known.space.b bVar2 = new org.wordpress.aztec.watchers.event.sequence.known.space.b(0);
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.b bVarC2 = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(0).c();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.b bVarE = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(2).e();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD3 = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1).d();
        bVar2.a.clear();
        bVar2.a(bVarC2);
        bVar2.a(bVarE);
        bVar2.a(cVarD3);
        arrayList2.add(bVar2);
        arrayList.add(aVar);
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public final boolean add(e element) {
        Intrinsics.checkNotNullParameter(element, "element");
        synchronized (this) {
            boolean zAdd = super.add(element);
            if (this.c.size() == 0) {
                return zAdd;
            }
            if (zAdd) {
                e();
            }
            return zAdd;
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ boolean contains(Object obj) {
        if (obj instanceof e) {
            return super.contains((e) obj);
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void e() {
        if (size() == 2 && ((e) get(1)).d - ((e) get(0)).d > 100) {
            remove(0);
        }
        Iterator it2 = this.c.iterator();
        boolean z = false;
        while (it2.hasNext()) {
            Iterator it3 = ((org.wordpress.aztec.watchers.event.buckets.a) it2.next()).a.iterator();
            while (it3.hasNext()) {
                c cVar = (c) it3.next();
                if (size() >= cVar.a.size()) {
                    b resultType = cVar.d(this);
                    Intrinsics.checkNotNullParameter(resultType, "resultType");
                    if (resultType == b.a) {
                        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c data = cVar.b(this);
                        AztecText aztecText = this.b;
                        aztecText.getClass();
                        Intrinsics.checkNotNullParameter(data, "data");
                        aztecText.p = true;
                        aztecText.setText(data.c.a);
                        aztecText.setSelection(data.f + data.g);
                        aztecText.p = false;
                        clear();
                    }
                    Intrinsics.checkNotNullParameter(resultType, "resultType");
                    if (resultType == b.c) {
                        clear();
                    }
                } else if (cVar.e(this)) {
                    z = true;
                }
            }
        }
        if (size() <= 0 || z) {
            return;
        }
        clear();
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public final /* bridge */ int indexOf(Object obj) {
        if (obj instanceof e) {
            return super.indexOf((e) obj);
        }
        return -1;
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public final /* bridge */ int lastIndexOf(Object obj) {
        if (obj instanceof e) {
            return super.lastIndexOf((e) obj);
        }
        return -1;
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ boolean remove(Object obj) {
        if (obj instanceof e) {
            return super.remove((e) obj);
        }
        return false;
    }
}
