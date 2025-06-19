package kotlinx.serialization.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* renamed from: kotlinx.serialization.internal.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5048d extends AbstractC5064s {
    public final /* synthetic */ int b;
    public final M c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C5048d(KSerializer eSerializer, int i) {
        this(eSerializer, (char) 0);
        this.b = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(eSerializer, "eSerializer");
                this(eSerializer, (char) 0);
                SerialDescriptor elementDesc = eSerializer.getDescriptor();
                Intrinsics.checkNotNullParameter(elementDesc, "elementDesc");
                this.c = new C5046c(elementDesc, 2);
                break;
            case 2:
                Intrinsics.checkNotNullParameter(eSerializer, "eSerializer");
                this(eSerializer, (char) 0);
                SerialDescriptor elementDesc2 = eSerializer.getDescriptor();
                Intrinsics.checkNotNullParameter(elementDesc2, "elementDesc");
                this.c = new C5046c(elementDesc2, 3);
                break;
            default:
                Intrinsics.checkNotNullParameter(eSerializer, "element");
                SerialDescriptor elementDesc3 = eSerializer.getDescriptor();
                Intrinsics.checkNotNullParameter(elementDesc3, "elementDesc");
                this.c = new C5046c(elementDesc3, 1);
                break;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object a() {
        switch (this.b) {
            case 0:
                return new ArrayList();
            case 1:
                return new HashSet();
            default:
                return new LinkedHashSet();
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int b(Object obj) {
        switch (this.b) {
            case 0:
                ArrayList arrayList = (ArrayList) obj;
                Intrinsics.checkNotNullParameter(arrayList, "<this>");
                return arrayList.size();
            case 1:
                HashSet hashSet = (HashSet) obj;
                Intrinsics.checkNotNullParameter(hashSet, "<this>");
                return hashSet.size();
            default:
                LinkedHashSet linkedHashSet = (LinkedHashSet) obj;
                Intrinsics.checkNotNullParameter(linkedHashSet, "<this>");
                return linkedHashSet.size();
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Iterator c(Object obj) {
        Collection collection = (Collection) obj;
        Intrinsics.checkNotNullParameter(collection, "<this>");
        return collection.iterator();
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        Collection collection = (Collection) obj;
        Intrinsics.checkNotNullParameter(collection, "<this>");
        return collection.size();
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        switch (this.b) {
            case 0:
                Intrinsics.checkNotNullParameter(null, "<this>");
                return new ArrayList((Collection) null);
            case 1:
                Intrinsics.checkNotNullParameter(null, "<this>");
                return new HashSet((Collection) null);
            default:
                Intrinsics.checkNotNullParameter(null, "<this>");
                return new LinkedHashSet((Collection) null);
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        switch (this.b) {
        }
        return (C5046c) this.c;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object h(Object obj) {
        switch (this.b) {
            case 0:
                ArrayList arrayList = (ArrayList) obj;
                Intrinsics.checkNotNullParameter(arrayList, "<this>");
                return arrayList;
            case 1:
                HashSet hashSet = (HashSet) obj;
                Intrinsics.checkNotNullParameter(hashSet, "<this>");
                return hashSet;
            default:
                LinkedHashSet linkedHashSet = (LinkedHashSet) obj;
                Intrinsics.checkNotNullParameter(linkedHashSet, "<this>");
                return linkedHashSet;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s
    public final void i(int i, Object obj, Object obj2) {
        switch (this.b) {
            case 0:
                ArrayList arrayList = (ArrayList) obj;
                Intrinsics.checkNotNullParameter(arrayList, "<this>");
                arrayList.add(i, obj2);
                break;
            case 1:
                HashSet hashSet = (HashSet) obj;
                Intrinsics.checkNotNullParameter(hashSet, "<this>");
                hashSet.add(obj2);
                break;
            default:
                LinkedHashSet linkedHashSet = (LinkedHashSet) obj;
                Intrinsics.checkNotNullParameter(linkedHashSet, "<this>");
                linkedHashSet.add(obj2);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5048d(KSerializer element, char c) {
        super(element);
        Intrinsics.checkNotNullParameter(element, "element");
    }
}
