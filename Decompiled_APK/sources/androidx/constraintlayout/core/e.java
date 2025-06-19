package androidx.constraintlayout.core;

import android.view.View;
import androidx.compose.animation.d0;
import androidx.core.view.L;
import androidx.core.view.V;
import assistantMode.refactored.modelTypes.MultipleChoiceOption;
import assistantMode.refactored.types.FillInTheBlankKeyphraseLocation;
import assistantMode.types.C1455b;
import com.comscore.streaming.EventType;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.Scope;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.v;

/* loaded from: classes.dex */
public final class e implements Comparator {
    public static final /* synthetic */ e b = new e(23);
    public static final /* synthetic */ e c = new e(25);
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                return ((g) obj).b - ((g) obj2).b;
            case 1:
                ((androidx.constraintlayout.core.motion.utils.f) obj).getClass();
                ((androidx.constraintlayout.core.motion.utils.f) obj2).getClass();
                return Integer.compare(0, 0);
            case 2:
                WeakHashMap weakHashMap = V.a;
                float fG = L.g((View) obj);
                float fG2 = L.g((View) obj2);
                if (fG > fG2) {
                    return -1;
                }
                return fG < fG2 ? 1 : 0;
            case 3:
                return ((androidx.viewpager.widget.c) obj).b - ((androidx.viewpager.widget.c) obj2).b;
            case 4:
                return ((int[]) obj)[0] - ((int[]) obj2)[0];
            case 5:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 6:
                return kotlin.comparisons.a.b(((MultipleChoiceOption) obj).c, ((MultipleChoiceOption) obj2).c);
            case 7:
                return kotlin.comparisons.a.b(Integer.valueOf(((FillInTheBlankKeyphraseLocation) ((v) obj).a).a), Integer.valueOf(((FillInTheBlankKeyphraseLocation) ((v) obj2).a).a));
            case 8:
                return kotlin.comparisons.a.b(Integer.valueOf(((FillInTheBlankKeyphraseLocation) obj).a), Integer.valueOf(((FillInTheBlankKeyphraseLocation) obj2).a));
            case 9:
                return kotlin.comparisons.a.b(Long.valueOf(((assistantMode.refactored.interfaces.c) obj).d()), Long.valueOf(((assistantMode.refactored.interfaces.c) obj2).d()));
            case 10:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 11:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 12:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 13:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj2).f), Long.valueOf(((C1455b) obj).f));
            case 14:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 15:
                return kotlin.comparisons.a.b((Double) ((Pair) obj2).b, (Double) ((Pair) obj).b);
            case 16:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj2).f), Long.valueOf(((C1455b) obj).f));
            case 17:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 18:
                return kotlin.comparisons.a.b((Double) ((Pair) obj).b, (Double) ((Pair) obj2).b);
            case 19:
                return kotlin.comparisons.a.b(Long.valueOf(((C1455b) obj).f), Long.valueOf(((C1455b) obj2).f));
            case 20:
                ((coil3.network.okhttp.internal.d) obj2).getClass();
                ((coil3.network.okhttp.internal.d) obj).getClass();
                return kotlin.comparisons.a.b(2, 2);
            case 21:
                throw d0.l(obj2);
            case EventType.WINDOW_STATE /* 22 */:
                return ((byte[]) obj).length - ((byte[]) obj2).length;
            case EventType.AUDIO /* 23 */:
                return ((Scope) obj).b.compareTo(((Scope) obj2).b);
            case EventType.VIDEO /* 24 */:
                return ((Scope) obj).b.compareTo(((Scope) obj2).b);
            case EventType.SUBS /* 25 */:
                Feature feature = (Feature) obj2;
                Feature feature2 = (Feature) obj;
                return !feature2.a.equals(feature.a) ? feature2.a.compareTo(feature.a) : Long.compare(feature2.a(), feature.a());
            case EventType.CDN /* 26 */:
                Map.Entry entry = (Map.Entry) obj;
                Map.Entry entry2 = (Map.Entry) obj2;
                Objects.requireNonNull(entry);
                Objects.requireNonNull(entry2);
                Comparable comparable = (Comparable) entry.getKey();
                Comparable comparable2 = (Comparable) entry2.getKey();
                comparable.getClass();
                comparable2.getClass();
                return comparable.compareTo(comparable2);
            case 27:
                return Long.compare(((Long) obj).longValue(), ((Long) obj2).longValue());
            case 28:
                return ((View) obj).getTop() - ((View) obj2).getTop();
            default:
                return ((Comparable) obj).compareTo((Comparable) obj2);
        }
    }
}
