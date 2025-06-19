package androidx.camera.core.internal.compat.workaround;

import android.media.MediaCodec;
import android.text.SpannableStringBuilder;
import androidx.camera.camera2.internal.compat.workaround.e;
import androidx.camera.core.X;
import androidx.camera.core.impl.C0166e;
import androidx.compose.animation.C0281h;
import androidx.navigation.compose.x;
import com.quizlet.db.data.models.persisted.DBTerm;
import java.text.Collator;
import java.util.Comparator;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.K;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Comparator {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        Object obj3;
        Object obj4;
        switch (this.a) {
            case 0:
                C0166e c0166e = (C0166e) obj2;
                ((e) this.b).getClass();
                Class cls = ((C0166e) obj).a.j;
                int i = 1;
                int i2 = cls == MediaCodec.class ? 2 : cls == X.class ? 0 : 1;
                Class cls2 = c0166e.a.j;
                if (cls2 == MediaCodec.class) {
                    i = 2;
                } else if (cls2 == X.class) {
                    i = 0;
                }
                return i2 - i;
            case 1:
                return ((Number) ((C0281h) this.b).invoke(obj, obj2)).intValue();
            case 2:
                Pair pair = (Pair) obj;
                Pair pair2 = (Pair) obj2;
                String word = null;
                String word2 = (pair == null || (obj4 = pair.a) == null) ? null : ((DBTerm) obj4).getWord();
                if (pair2 != null && (obj3 = pair2.a) != null) {
                    word = ((DBTerm) obj3).getWord();
                }
                Collator collator = (Collator) this.b;
                Intrinsics.checkNotNullParameter(collator, "<this>");
                Intrinsics.checkNotNullParameter(collator, "<this>");
                if (word2 == word) {
                    return 0;
                }
                if (word2 == null) {
                    return -1;
                }
                if (word == null) {
                    return 1;
                }
                return collator.compare(word2, word);
            case 3:
                return ((Number) ((x) this.b).invoke(obj, obj2)).intValue();
            case 4:
                for (Function1 function1 : (Function1[]) this.b) {
                    int iB = kotlin.comparisons.a.b((Comparable) function1.invoke(obj), (Comparable) function1.invoke(obj2));
                    if (iB != 0) {
                        return iB;
                    }
                }
                return 0;
            default:
                K k = (K) obj;
                K k2 = (K) obj2;
                SpannableStringBuilder text = (SpannableStringBuilder) this.b;
                Intrinsics.checkNotNullParameter(text, "$text");
                int iG = Intrinsics.g(text.getSpanStart(k), text.getSpanStart(k2));
                if (iG != 0) {
                    return iG;
                }
                int iG2 = Intrinsics.g(k.a(), k2.a());
                return iG2 == 0 ? Intrinsics.g(text.getSpanEnd(k), text.getSpanEnd(k2)) : iG2;
        }
    }
}
