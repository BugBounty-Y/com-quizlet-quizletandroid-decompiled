package assistantMode.grading;

import assistantMode.types.Feedback;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public p j;
    public v k;
    public J2 l;
    public Feedback m;
    public h n;
    public Iterator o;
    public /* synthetic */ Object p;
    public final /* synthetic */ p q;
    public int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.q = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.p = obj;
        this.r |= Integer.MIN_VALUE;
        return this.q.a(null, null, this);
    }
}
