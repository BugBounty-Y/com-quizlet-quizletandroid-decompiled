package androidx.camera.camera2.internal;

import android.graphics.Rect;
import android.util.Size;
import androidx.camera.core.impl.C0162c;
import com.braze.models.cards.Card;
import com.braze.ui.BrazeFeedFragment;
import com.braze.ui.contentcards.BrazeContentCardUtils;
import com.quizlet.db.data.models.base.Comparators;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.eventlogger.model.EditActionsLog;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.util.Comparator;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class a0 implements Comparator {
    public final /* synthetic */ int a;

    public /* synthetic */ a0(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Size size = (Size) obj;
                Size size2 = (Size) obj2;
                return Long.signum((size.getWidth() * size.getHeight()) - (size2.getWidth() * size2.getHeight()));
            case 1:
                return ((C0162c) obj).a.compareTo(((C0162c) obj2).a);
            case 2:
                return Intrinsics.g(((androidx.compose.runtime.O) obj).b, ((androidx.compose.runtime.O) obj2).b);
            case 3:
                androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) obj;
                androidx.compose.ui.node.E e2 = (androidx.compose.ui.node.E) obj2;
                float f = e.x.r.z;
                float f2 = e2.x.r.z;
                return f == f2 ? Intrinsics.g(e.t(), e2.t()) : Float.compare(f, f2);
            case 4:
                androidx.compose.ui.semantics.o oVar = (androidx.compose.ui.semantics.o) obj2;
                androidx.compose.ui.semantics.k kVar = ((androidx.compose.ui.semantics.o) obj).d;
                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.n;
                Object objValueOf = kVar.a.get(uVar);
                if (objValueOf == null) {
                    objValueOf = Float.valueOf(DefinitionKt.NO_Float_VALUE);
                }
                float fFloatValue = ((Number) objValueOf).floatValue();
                Object objValueOf2 = oVar.d.a.get(uVar);
                if (objValueOf2 == null) {
                    objValueOf2 = Float.valueOf(DefinitionKt.NO_Float_VALUE);
                }
                return Float.compare(fFloatValue, ((Number) objValueOf2).floatValue());
            case 5:
                Pair pair = (Pair) obj;
                Pair pair2 = (Pair) obj2;
                return (((Number) pair.b).intValue() - ((Number) pair.a).intValue()) - (((Number) pair2.b).intValue() - ((Number) pair2.a).intValue());
            case 6:
                return Integer.parseInt(((String) obj).split(":")[0]) - Integer.parseInt(((String) obj2).split(":")[0]);
            case 7:
                byte[] bArr = (byte[]) obj;
                byte[] bArr2 = (byte[]) obj2;
                if (bArr.length != bArr2.length) {
                    return bArr.length - bArr2.length;
                }
                for (int i = 0; i < bArr.length; i++) {
                    byte b = bArr[i];
                    byte b2 = bArr2[i];
                    if (b != b2) {
                        return b - b2;
                    }
                }
                return 0;
            case 8:
                return com.braze.triggers.utils.b.a((com.braze.triggers.actions.a) obj, (com.braze.triggers.actions.a) obj2);
            case 9:
                return BrazeFeedFragment.lambda$sortFeedCards$4((Card) obj, (Card) obj2);
            case 10:
                return BrazeContentCardUtils.defaultCardHandling$lambda$0((Card) obj, (Card) obj2);
            case 11:
                com.facebook.internal.instrument.c cVar = (com.facebook.internal.instrument.c) obj;
                com.facebook.internal.instrument.c data = (com.facebook.internal.instrument.c) obj2;
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.internal.instrument.anrreport.c.class)) {
                    try {
                        Intrinsics.checkNotNullExpressionValue(data, "o2");
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(data, "data");
                        Long l = cVar.g;
                        if (l == null) {
                            return -1;
                        }
                        long jLongValue = l.longValue();
                        Long l2 = data.g;
                        if (l2 != null) {
                            return Intrinsics.h(l2.longValue(), jLongValue);
                        }
                        return 1;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.internal.instrument.anrreport.c.class, th);
                    }
                }
                return 0;
            case 12:
                com.facebook.internal.instrument.c cVar2 = (com.facebook.internal.instrument.c) obj;
                com.facebook.internal.instrument.c data2 = (com.facebook.internal.instrument.c) obj2;
                Intrinsics.checkNotNullExpressionValue(data2, "o2");
                cVar2.getClass();
                Intrinsics.checkNotNullParameter(data2, "data");
                Long l3 = cVar2.g;
                if (l3 == null) {
                    return -1;
                }
                long jLongValue2 = l3.longValue();
                Long l4 = data2.g;
                if (l4 != null) {
                    return Intrinsics.h(l4.longValue(), jLongValue2);
                }
                return 1;
            case 13:
                com.facebook.internal.instrument.errorreport.a aVar = (com.facebook.internal.instrument.errorreport.a) obj;
                com.facebook.internal.instrument.errorreport.a data3 = (com.facebook.internal.instrument.errorreport.a) obj2;
                Intrinsics.checkNotNullExpressionValue(data3, "o2");
                aVar.getClass();
                Intrinsics.checkNotNullParameter(data3, "data");
                Long l5 = aVar.c;
                if (l5 == null) {
                    return -1;
                }
                long jLongValue3 = l5.longValue();
                Long l6 = data3.c;
                if (l6 != null) {
                    return Intrinsics.h(l6.longValue(), jLongValue3);
                }
                return 1;
            case 14:
                return Long.compare(((File) obj2).lastModified(), ((File) obj).lastModified());
            case 15:
                return ((com.google.firebase.crashlytics.internal.model.F) ((com.google.firebase.crashlytics.internal.model.r0) obj)).a.compareTo(((com.google.firebase.crashlytics.internal.model.F) ((com.google.firebase.crashlytics.internal.model.r0) obj2)).a);
            case 16:
                return ((File) obj2).getName().compareTo(((File) obj).getName());
            case 17:
                String name = ((File) obj).getName();
                int i2 = com.google.firebase.crashlytics.internal.persistence.a.f;
                return name.substring(0, i2).compareTo(((File) obj2).getName().substring(0, i2));
            case 18:
                return ((com.quizlet.android.migrator.migrations.a) obj).getVersion().compareTo(((com.quizlet.android.migrator.migrations.a) obj2).getVersion());
            case 19:
                return Comparators.DEFAULT_ASC$lambda$0((DBModel) obj, (DBModel) obj2);
            case 20:
                return Comparators.DEFAULT_DESC$lambda$1((DBModel) obj, (DBModel) obj2);
            case 21:
                EditActionsLog editActionsLog = (EditActionsLog) obj;
                EditActionsLog editActionsLog2 = (EditActionsLog) obj2;
                int time = (int) (editActionsLog.getTimestamp().getTime() - editActionsLog2.getTimestamp().getTime());
                return time != 0 ? time : editActionsLog.getAction().compareTo(editActionsLog2.getAction());
            default:
                Rect rect = (Rect) obj;
                Rect rect2 = (Rect) obj2;
                return -Float.compare(rect.height() * rect.width(), rect2.height() * rect2.width());
        }
    }
}
