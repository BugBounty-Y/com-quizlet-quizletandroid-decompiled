package com.quizlet.local.ormlite.models.folderwithcreator;

import com.quizlet.data.model.CreatedFolder;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("folders", list);
                for (Object obj2 : list) {
                    if (obj2 instanceof CreatedFolder) {
                        arrayListM.add(obj2);
                    }
                }
                return arrayListM;
            default:
                List folders = (List) obj;
                Intrinsics.checkNotNullParameter(folders, "folders");
                ArrayList arrayList = new ArrayList(C.q(folders, 10));
                Iterator it2 = folders.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((CreatedFolder) it2.next()).h()));
                }
                return arrayList;
        }
    }
}
