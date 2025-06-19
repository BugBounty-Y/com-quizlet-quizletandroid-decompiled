package assistantMode.stepGenerators.types;

import androidx.compose.animation.d0;
import assistantMode.refactored.types.Checkpoint;
import assistantMode.refactored.types.d;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends Y2 {
    public final d a;
    public final Checkpoint b;
    public final double c;
    public final assistantMode.refactored.types.c d;
    public final Integer e;
    public final Integer f;

    public a(d dVar, Checkpoint checkpoint, double d, assistantMode.refactored.types.c masteryBuckets, Integer num, Integer num2, int i) {
        dVar = (i & 1) != 0 ? null : dVar;
        checkpoint = (i & 2) != 0 ? null : checkpoint;
        Intrinsics.checkNotNullParameter(masteryBuckets, "masteryBuckets");
        this.a = dVar;
        this.b = checkpoint;
        this.c = d;
        this.d = masteryBuckets;
        this.e = num;
        this.f = num2;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Y2
    public final Checkpoint b() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Y2
    public final d d() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Double.compare(this.c, aVar.c) == 0 && this.d.equals(aVar.d) && this.e.equals(aVar.e) && this.f.equals(aVar.f);
    }

    public final int hashCode() {
        d dVar = this.a;
        int iHashCode = (dVar == null ? 0 : dVar.hashCode()) * 31;
        Checkpoint checkpoint = this.b;
        return this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + d0.a(this.c, (iHashCode + (checkpoint != null ? checkpoint.hashCode() : 0)) * 961, 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AssistantStep(question=");
        sb.append(this.a);
        sb.append(", checkpoint=");
        sb.append(this.b);
        sb.append(", roundProgress=null, studyProgress=");
        sb.append(this.c);
        sb.append(", masteryBuckets=");
        sb.append(this.d);
        sb.append(", completedRoundUnits=");
        sb.append(this.e);
        sb.append(", totalRoundUnits=");
        return assistantMode.refactored.a.l(sb, this.f, ")");
    }
}
