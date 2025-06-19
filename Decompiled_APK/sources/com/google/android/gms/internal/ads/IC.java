package com.google.android.gms.internal.ads;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* loaded from: classes2.dex */
public final class IC implements CC {
    public static final /* synthetic */ int c = 0;
    public final List a;
    public final List b;

    static {
        DC.a(Collections.EMPTY_SET);
    }

    public /* synthetic */ IC(List list, List list2) {
        this.a = list;
        this.b = list2;
    }

    public static Ps a(int i, int i2) {
        return new Ps(i, i2);
    }

    @Override // com.google.android.gms.internal.ads.HC
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    public final Set zzb() {
        List list = this.a;
        int size = list.size();
        List list2 = this.b;
        ArrayList arrayList = new ArrayList(list2.size());
        int size2 = list2.size();
        for (int i = 0; i < size2; i++) {
            Collection collection = (Collection) ((HC) list2.get(i)).zzb();
            size += collection.size();
            arrayList.add(collection);
        }
        HashSet hashSet = new HashSet(size < 3 ? size + 1 : size < 1073741824 ? (int) ((size / 0.75f) + 1.0f) : SubsamplingScaleImageView.TILE_SIZE_AUTO);
        int size3 = list.size();
        for (int i2 = 0; i2 < size3; i2++) {
            Object objZzb = ((HC) list.get(i2)).zzb();
            objZzb.getClass();
            hashSet.add(objZzb);
        }
        int size4 = arrayList.size();
        for (int i3 = 0; i3 < size4; i3++) {
            for (Object obj : (Collection) arrayList.get(i3)) {
                obj.getClass();
                hashSet.add(obj);
            }
        }
        return Collections.unmodifiableSet(hashSet);
    }
}
