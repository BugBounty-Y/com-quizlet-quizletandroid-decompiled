package androidx.cursoradapter.widget;

import android.database.Cursor;
import android.widget.Filter;
import android.widget.Filterable;
import androidx.appcompat.widget.j1;
import com.quizlet.quizletandroid.ui.setcreation.adapters.c;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class b extends Filter {
    public final /* synthetic */ int a = 0;
    public Filterable b;

    public /* synthetic */ b() {
    }

    public ArrayList a(ArrayList arrayList, CharSequence charSequence) {
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            String string = charSequence.toString();
            Locale locale = Locale.ROOT;
            String lowerCase = string.toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            String strD = ((c) this.b).a.d(str);
            boolean zG = false;
            if (strD != null) {
                String lowerCase2 = strD.toLowerCase(locale);
                Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
                if (lowerCase2 != null) {
                    zG = StringsKt.G(lowerCase2, lowerCase, false);
                }
            }
            if (zG) {
                arrayList2.add(str);
            }
        }
        return arrayList2;
    }

    @Override // android.widget.Filter
    public CharSequence convertResultToString(Object obj) {
        switch (this.a) {
            case 0:
                return ((j1) ((a) this.b)).c((Cursor) obj);
            default:
                return super.convertResultToString(obj);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x009e  */
    @Override // android.widget.Filter
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.widget.Filter.FilterResults performFiltering(java.lang.CharSequence r8) {
        /*
            r7 = this;
            r0 = 1
            r1 = 2
            r2 = 0
            int r3 = r7.a
            switch(r3) {
                case 0: goto L68;
                default: goto L8;
            }
        L8:
            java.lang.String r3 = "constraint"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r3)
            android.widget.Filter$FilterResults r3 = new android.widget.Filter$FilterResults
            r3.<init>()
            int r4 = r8.length()
            android.widget.Filterable r5 = r7.b
            com.quizlet.quizletandroid.ui.setcreation.adapters.c r5 = (com.quizlet.quizletandroid.ui.setcreation.adapters.c) r5
            if (r4 != 0) goto L38
            java.lang.ref.WeakReference r8 = r5.d
            java.lang.Object r8 = r8.get()
            kotlin.jvm.internal.Intrinsics.d(r8)
            com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.c r8 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.c) r8
            com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity r8 = (com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity) r8
            java.util.ArrayList r4 = r8.p
            java.util.ArrayList r8 = r8.q
            java.util.List[] r1 = new java.util.List[r1]
            r1[r2] = r4
            r1[r0] = r8
            java.util.ArrayList r8 = kotlin.collections.B.k(r1)
            goto L65
        L38:
            java.lang.ref.WeakReference r4 = r5.d
            java.lang.Object r4 = r4.get()
            kotlin.jvm.internal.Intrinsics.d(r4)
            com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.c r4 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.c) r4
            com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity r4 = (com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity) r4
            java.util.ArrayList r5 = r4.p
            java.lang.String r6 = "getTopLanguageCodes(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            java.util.ArrayList r5 = r7.a(r5, r8)
            java.util.ArrayList r4 = r4.q
            java.lang.String r6 = "getAllLanguageCodes(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r6)
            java.util.ArrayList r8 = r7.a(r4, r8)
            java.util.List[] r1 = new java.util.List[r1]
            r1[r2] = r5
            r1[r0] = r8
            java.util.ArrayList r8 = kotlin.collections.B.k(r1)
        L65:
            r3.values = r8
            return r3
        L68:
            android.widget.Filterable r0 = r7.b
            androidx.cursoradapter.widget.a r0 = (androidx.cursoradapter.widget.a) r0
            androidx.appcompat.widget.j1 r0 = (androidx.appcompat.widget.j1) r0
            if (r8 != 0) goto L73
            java.lang.String r8 = ""
            goto L7a
        L73:
            r0.getClass()
            java.lang.String r8 = r8.toString()
        L7a:
            androidx.appcompat.widget.SearchView r1 = r0.k
            int r3 = r1.getVisibility()
            r4 = 0
            if (r3 != 0) goto L9e
            int r1 = r1.getWindowVisibility()
            if (r1 == 0) goto L8a
            goto L9e
        L8a:
            android.app.SearchableInfo r1 = r0.l     // Catch: java.lang.RuntimeException -> L96
            android.database.Cursor r8 = r0.j(r1, r8)     // Catch: java.lang.RuntimeException -> L96
            if (r8 == 0) goto L9e
            r8.getCount()     // Catch: java.lang.RuntimeException -> L96
            goto L9f
        L96:
            r8 = move-exception
            java.lang.String r0 = "SuggestionsAdapter"
            java.lang.String r1 = "Search suggestions query threw an exception."
            android.util.Log.w(r0, r1, r8)
        L9e:
            r8 = r4
        L9f:
            android.widget.Filter$FilterResults r0 = new android.widget.Filter$FilterResults
            r0.<init>()
            if (r8 == 0) goto Laf
            int r1 = r8.getCount()
            r0.count = r1
            r0.values = r8
            goto Lb3
        Laf:
            r0.count = r2
            r0.values = r4
        Lb3:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.cursoradapter.widget.b.performFiltering(java.lang.CharSequence):android.widget.Filter$FilterResults");
    }

    @Override // android.widget.Filter
    public final void publishResults(CharSequence constraint, Filter.FilterResults results) {
        switch (this.a) {
            case 0:
                a aVar = (a) this.b;
                Cursor cursor = aVar.c;
                Object obj = results.values;
                if (obj != null && obj != cursor) {
                    ((j1) aVar).b((Cursor) obj);
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(constraint, "constraint");
                Intrinsics.checkNotNullParameter(results, "results");
                c cVar = (c) this.b;
                cVar.getClass();
                Intrinsics.checkNotNullParameter(constraint, "<set-?>");
                cVar.e = constraint;
                Object obj2 = results.values;
                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.collections.List<kotlin.String>>");
                List listB = O.b(obj2);
                cVar.getClass();
                Intrinsics.checkNotNullParameter(listB, "<set-?>");
                cVar.c = listB;
                cVar.notifyDataSetChanged();
                break;
        }
    }

    public b(c cVar) {
        this.b = cVar;
    }
}
