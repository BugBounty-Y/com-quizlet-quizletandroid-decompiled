package androidx.activity;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.s0;

/* renamed from: androidx.activity.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0034f implements androidx.savedstate.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C0034f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.savedstate.c
    public final Bundle a() {
        Pair[] pairArr;
        switch (this.a) {
            case 0:
                return s.n((s) this.b);
            case 1:
                Map mapB = ((androidx.compose.runtime.saveable.j) this.b).b();
                Bundle bundle = new Bundle();
                for (Map.Entry entry : mapB.entrySet()) {
                    String str = (String) entry.getKey();
                    List list = (List) entry.getValue();
                    bundle.putParcelableArrayList(str, list instanceof ArrayList ? (ArrayList) list : new ArrayList<>(list));
                }
                return bundle;
            default:
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = (com.quizlet.data.repository.studysetwithcreatorinclass.g) this.b;
                for (Map.Entry entry2 : V.l((LinkedHashMap) gVar.e).entrySet()) {
                    gVar.s(((s0) ((X) entry2.getValue())).getValue(), (String) entry2.getKey());
                }
                for (Map.Entry entry3 : V.l((LinkedHashMap) gVar.c).entrySet()) {
                    gVar.s(((androidx.savedstate.c) entry3.getValue()).a(), (String) entry3.getKey());
                }
                LinkedHashMap linkedHashMap = (LinkedHashMap) gVar.b;
                if (linkedHashMap.isEmpty()) {
                    pairArr = new Pair[0];
                } else {
                    ArrayList arrayList = new ArrayList(linkedHashMap.size());
                    for (Map.Entry entry4 : linkedHashMap.entrySet()) {
                        arrayList.add(new Pair((String) entry4.getKey(), entry4.getValue()));
                    }
                    pairArr = (Pair[]) arrayList.toArray(new Pair[0]);
                }
                Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(pairArr, pairArr.length));
                Intrinsics.checkNotNullParameter(source, "source");
                return source;
        }
    }
}
