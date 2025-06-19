package com.quizlet.remote.model.folderstudymaterial;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.generated.enums.y1;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.service.o;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public com.quizlet.remote.model.base.a j;
    public int k;
    public final /* synthetic */ j l;
    public final /* synthetic */ long m;
    public final /* synthetic */ List n;
    public final /* synthetic */ boolean o;
    public final /* synthetic */ boolean p;
    public final /* synthetic */ PagingInfo q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(j jVar, long j, List list, boolean z, boolean z2, PagingInfo pagingInfo, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = jVar;
        this.m = j;
        this.n = list;
        this.o = z;
        this.p = z2;
        this.q = pagingInfo;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        com.quizlet.remote.model.base.a aVar;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                j jVar = this.l;
                long j = this.m;
                List list = this.n;
                com.quizlet.remote.model.base.a aVar3 = com.quizlet.remote.model.base.a.a;
                o oVar = jVar.a;
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(new Integer(((y1) it2.next()).b()));
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                if (this.o) {
                    linkedHashMap.putAll(V.f(new Pair("include[folderStudyMaterial][folder]", "user"), new Pair("include[folderStudyMaterial][set]", AssociationNames.CREATOR)));
                }
                if (this.p) {
                    linkedHashMap.putAll(U.b(new Pair("filters[isDeleted]", "false")));
                }
                PagingInfo pagingInfo = this.q;
                if (pagingInfo != null) {
                    linkedHashMap.putAll(pagingInfo.a());
                }
                Unit unit = Unit.a;
                this.j = aVar3;
                this.k = 1;
                obj = oVar.e(j, arrayList, linkedHashMap, this);
                if (obj == aVar2) {
                    return aVar2;
                }
                aVar = aVar3;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                aVar = this.j;
                Z.e(obj);
            }
            objB = com.google.android.gms.internal.mlkit_vision_barcode.V.c((ApiThreeWrapper) obj, aVar);
        } catch (Exception e) {
            p pVar = r.b;
            objB = Z.b(e);
        }
        return new r(objB);
    }
}
