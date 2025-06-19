package androidx.core.view;

import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import java.util.Iterator;
import kotlin.sequences.Sequence;

/* loaded from: classes.dex */
public final class X implements Sequence {
    final /* synthetic */ ViewGroup a;

    public X(RecyclerView recyclerView) {
        this.a = recyclerView;
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        return new Y(this.a);
    }
}
