package com.google.zxing.aztec.encoder;

import android.content.pm.ShortcutInfo;
import androidx.camera.core.impl.utils.executor.i;
import com.android.billingclient.api.Purchase;
import com.comscore.streaming.EventType;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.B1;
import com.quizlet.data.model.C4169u;
import com.quizlet.data.model.CreatedFolderWithCreator;
import com.quizlet.data.model.M1;
import com.quizlet.data.model.N1;
import com.quizlet.data.model.RecommendedStudyMaterial;
import com.quizlet.features.setpage.termlist.data.j;
import com.quizlet.ui.models.content.listitem.h;
import com.quizlet.ui.models.content.listitem.o;
import java.time.DayOfWeek;
import java.util.Comparator;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.D;

/* loaded from: classes2.dex */
public final class c implements Comparator {
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) throws JSONException {
        String lowerCase;
        String lowerCase2;
        String lowerCase3;
        switch (this.a) {
            case 0:
                return ((f) obj).d - ((f) obj2).d;
            case 1:
                JSONObject jSONObject = (JSONObject) obj2;
                String lowerCase4 = "";
                try {
                    String string = ((JSONObject) obj).getString("name");
                    Locale locale = Locale.ENGLISH;
                    lowerCase = string.toLowerCase(locale);
                    try {
                        lowerCase4 = jSONObject.getString("name").toLowerCase(locale);
                    } catch (JSONException e) {
                        e = e;
                        Z.o("error while sorting VL json object lists,err : ", e, "TVGoogleVendors");
                        return lowerCase.compareTo(lowerCase4);
                    }
                } catch (JSONException e2) {
                    e = e2;
                    lowerCase = "";
                }
                return lowerCase.compareTo(lowerCase4);
            case 2:
                JSONObject jSONObject2 = (JSONObject) obj2;
                String lowerCase5 = "";
                try {
                    String string2 = ((JSONObject) obj).getString("Name");
                    Locale locale2 = Locale.ENGLISH;
                    lowerCase2 = string2.toLowerCase(locale2);
                    try {
                        lowerCase5 = jSONObject2.getString("Name").toLowerCase(locale2);
                    } catch (JSONException e3) {
                        e = e3;
                        Z.o("error while sorting VL json object lists,err : ", e, "TVSdkList");
                        return lowerCase2.compareTo(lowerCase5);
                    }
                } catch (JSONException e4) {
                    e = e4;
                    lowerCase2 = "";
                }
                return lowerCase2.compareTo(lowerCase5);
            case 3:
                JSONObject jSONObject3 = (JSONObject) obj2;
                String lowerCase6 = "";
                try {
                    String string3 = ((JSONObject) obj).getString("name");
                    Locale locale3 = Locale.ENGLISH;
                    lowerCase3 = string3.toLowerCase(locale3);
                    try {
                        lowerCase6 = jSONObject3.getString("name").toLowerCase(locale3);
                    } catch (JSONException e5) {
                        e = e5;
                        Z.o("error while sorting VL json object lists,err : ", e, "TVVendorlist");
                        return lowerCase3.compareTo(lowerCase6);
                    }
                } catch (JSONException e6) {
                    e = e6;
                    lowerCase3 = "";
                }
                return lowerCase3.compareTo(lowerCase6);
            case 4:
                return kotlin.comparisons.a.b((Integer) obj, (Integer) obj2);
            case 5:
                com.google.android.material.shape.e eVar = com.perimeterx.mobile_sdk.models.e.a;
                String str = ((com.perimeterx.mobile_sdk.models.d) obj).a;
                eVar.getClass();
                com.perimeterx.mobile_sdk.models.e eVarH = com.google.android.material.shape.e.h(str);
                Integer numValueOf = eVarH != null ? Integer.valueOf(eVarH.a()) : 0;
                com.perimeterx.mobile_sdk.models.e eVarH2 = com.google.android.material.shape.e.h(((com.perimeterx.mobile_sdk.models.d) obj2).a);
                return kotlin.comparisons.a.b(numValueOf, eVarH2 != null ? Integer.valueOf(eVarH2.a()) : 0);
            case 6:
                return kotlin.comparisons.a.b(Long.valueOf(((Purchase) obj).c.optLong("purchaseTime")), Long.valueOf(((Purchase) obj2).c.optLong("purchaseTime")));
            case 7:
                return kotlin.comparisons.a.b(((C4169u) obj).b, ((C4169u) obj2).b);
            case 8:
                return kotlin.comparisons.a.b(Integer.valueOf(((B1) obj).b), Integer.valueOf(((B1) obj2).b));
            case 9:
                return kotlin.comparisons.a.b(Long.valueOf(((com.quizlet.explanations.myexplanations.data.a) obj2).a()), Long.valueOf(((com.quizlet.explanations.myexplanations.data.a) obj).a()));
            case 10:
                return kotlin.comparisons.a.b(Integer.valueOf(i.b((DayOfWeek) obj)), Integer.valueOf(i.b((DayOfWeek) obj2)));
            case 11:
                return kotlin.comparisons.a.b(Long.valueOf(((o) obj).a()), Long.valueOf(((o) obj2).a()));
            case 12:
                return kotlin.comparisons.a.b(Long.valueOf(((o) obj2).a()), Long.valueOf(((o) obj).a()));
            case 13:
                return kotlin.comparisons.a.b(((o) obj).getName(), ((o) obj2).getName());
            case 14:
                return kotlin.comparisons.a.b(((o) obj2).getName(), ((o) obj).getName());
            case 15:
                M1 m1A = ((N1) obj).a();
                Intrinsics.e(m1A, "null cannot be cast to non-null type com.quizlet.data.model.RecommendedStudyMaterial");
                Integer numValueOf2 = Integer.valueOf(((RecommendedStudyMaterial) m1A).c);
                M1 m1A2 = ((N1) obj2).a();
                Intrinsics.e(m1A2, "null cannot be cast to non-null type com.quizlet.data.model.RecommendedStudyMaterial");
                return kotlin.comparisons.a.b(numValueOf2, Integer.valueOf(((RecommendedStudyMaterial) m1A2).c));
            case 16:
                return kotlin.comparisons.a.b(Long.valueOf(((h) obj).c), Long.valueOf(((h) obj2).c));
            case 17:
                return kotlin.comparisons.a.b(((j) obj).b.a, ((j) obj2).b.a);
            case 18:
                return kotlin.comparisons.a.b(Long.valueOf(((com.quizlet.progress.types.a) obj).b), Long.valueOf(((com.quizlet.progress.types.a) obj2).b));
            case 19:
                return kotlin.comparisons.a.b(Long.valueOf(((CreatedFolderWithCreator) obj2).a.a()), Long.valueOf(((CreatedFolderWithCreator) obj).a.a()));
            case 20:
                return kotlin.comparisons.a.b(Long.valueOf(((CreatedFolderWithCreator) obj2).a.a()), Long.valueOf(((CreatedFolderWithCreator) obj).a.a()));
            case 21:
                return kotlin.comparisons.a.b(Integer.valueOf(((ShortcutInfo) obj).getRank()), Integer.valueOf(((ShortcutInfo) obj2).getRank()));
            case EventType.WINDOW_STATE /* 22 */:
                return kotlin.comparisons.a.b(Integer.valueOf(((ShortcutInfo) obj).getRank()), Integer.valueOf(((ShortcutInfo) obj2).getRank()));
            case EventType.AUDIO /* 23 */:
                return kotlin.comparisons.a.b(Integer.valueOf(((RecommendedStudyMaterial) obj).c), Integer.valueOf(((RecommendedStudyMaterial) obj2).c));
            case EventType.VIDEO /* 24 */:
                return ((Comparable) obj).compareTo((Comparable) obj2);
            case EventType.SUBS /* 25 */:
                return kotlin.comparisons.a.b(((okio.internal.h) obj).a, ((okio.internal.h) obj2).a);
            case EventType.CDN /* 26 */:
                return kotlin.comparisons.a.b(Integer.valueOf(((C5164l) obj).a), Integer.valueOf(((C5164l) obj2).a));
            default:
                return kotlin.comparisons.a.b(Integer.valueOf(((D) obj).a()), Integer.valueOf(((D) obj2).a()));
        }
    }
}
