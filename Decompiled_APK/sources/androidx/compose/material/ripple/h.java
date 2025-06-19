package androidx.compose.material.ripple;

import android.content.Context;
import android.view.ViewGroup;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class h extends ViewGroup {
    public final int a;
    public final ArrayList b;
    public final ArrayList c;
    public final com.quizlet.data.interactor.school.b d;
    public int e;

    public h(@NotNull Context context) {
        super(context);
        this.a = 5;
        ArrayList arrayList = new ArrayList();
        this.b = arrayList;
        ArrayList arrayList2 = new ArrayList();
        this.c = arrayList2;
        this.d = new com.quizlet.data.interactor.school.b(3);
        setClipChildren(false);
        j jVar = new j(context);
        addView(jVar);
        arrayList.add(jVar);
        arrayList2.add(jVar);
        this.e = 1;
        setTag(R.id.hide_in_inspector_tag, Boolean.TRUE);
    }

    public final j a(i iVar) {
        com.quizlet.data.interactor.school.b bVar = this.d;
        j jVar = (j) ((LinkedHashMap) bVar.b).get(iVar);
        if (jVar != null) {
            return jVar;
        }
        ArrayList arrayList = this.c;
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        j jVar2 = (j) (arrayList.isEmpty() ? null : arrayList.remove(0));
        LinkedHashMap linkedHashMap = (LinkedHashMap) bVar.b;
        LinkedHashMap linkedHashMap2 = (LinkedHashMap) bVar.c;
        if (jVar2 == null) {
            int i = this.e;
            ArrayList arrayList2 = this.b;
            if (i > B.i(arrayList2)) {
                jVar2 = new j(getContext());
                addView(jVar2);
                arrayList2.add(jVar2);
            } else {
                jVar2 = (j) arrayList2.get(this.e);
                i iVar2 = (i) linkedHashMap2.get(jVar2);
                if (iVar2 != null) {
                    iVar2.H();
                    j jVar3 = (j) linkedHashMap.get(iVar2);
                    if (jVar3 != null) {
                    }
                    linkedHashMap.remove(iVar2);
                    jVar2.c();
                }
            }
            int i2 = this.e;
            if (i2 < this.a - 1) {
                this.e = i2 + 1;
            } else {
                this.e = 0;
            }
        }
        linkedHashMap.put(iVar, jVar2);
        linkedHashMap2.put(jVar2, iVar);
        return jVar2;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        setMeasuredDimension(0, 0);
    }

    @Override // android.view.View, android.view.ViewParent
    public final void requestLayout() {
    }
}
