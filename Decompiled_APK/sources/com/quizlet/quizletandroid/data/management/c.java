package com.quizlet.quizletandroid.data.management;

import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements h, i {
    public static final c b = new c(0);
    public static final c c = new c(1);
    public static final c d = new c(2);
    public static final c e = new c(3);
    public static final c f = new c(4);
    public static final c g = new c(5);
    public static final c h = new c(6);
    public static final c i = new c(7);
    public static final c j = new c(8);
    public static final c k = new c(9);
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i2) {
        this.a = i2;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        DBImage image;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((Throwable) obj, "<unused var>");
                return p.f(Boolean.FALSE);
            case 1:
                Intrinsics.checkNotNullParameter((File) obj, "<unused var>");
                return Unit.a;
            case 2:
                List managerList = (List) obj;
                Intrinsics.checkNotNullParameter(managerList, "managerList");
                ArrayList arrayList = new ArrayList(C.q(managerList, 10));
                Iterator it2 = managerList.iterator();
                while (it2.hasNext()) {
                    arrayList.add(((a) it2.next()).a);
                }
                return arrayList;
            case 3:
                Intrinsics.checkNotNullParameter((a) obj, "<unused var>");
                return Boolean.TRUE;
            case 4:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                DBImageRef dBImageRef = (DBImageRef) CollectionsKt.firstOrNull(list);
                return com.google.android.gms.common.wrappers.a.d((dBImageRef == null || (image = dBImageRef.getImage()) == null) ? null : image.getMediumUrl());
            case 5:
                Intrinsics.checkNotNullParameter(obj, "<unused var>");
                return Boolean.TRUE;
            case 6:
                return com.google.android.gms.common.wrappers.a.d(((DBImageRef) obj).getImage().getMediumUrl());
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                return list2.size() > 0 ? io.reactivex.rxjava3.core.g.c(list2) : io.reactivex.rxjava3.internal.operators.maybe.f.a;
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 8:
                Boolean available = (Boolean) obj;
                Intrinsics.checkNotNullParameter(available, "available");
                return available.booleanValue();
            default:
                Boolean available2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(available2, "available");
                return available2.booleanValue();
        }
    }
}
