package assistantMode.stepGenerators.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.refactored.types.Checkpoint;
import assistantMode.refactored.types.Task;
import assistantMode.refactored.types.d;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends Y2 {
    public final d a;
    public final Checkpoint b;
    public final k c;
    public final Integer d;
    public final Double e;
    public final Integer f;
    public final Task g;
    public final double h;
    public final double i;

    public b(d dVar, Checkpoint checkpoint, k kVar, Integer num, Double d, Integer num2, Task task, double d2, double d3) {
        this.a = dVar;
        this.b = checkpoint;
        this.c = kVar;
        this.d = num;
        this.e = d;
        this.f = num2;
        this.g = task;
        this.h = d2;
        this.i = d3;
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
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && this.c == bVar.c && Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e) && Intrinsics.b(this.f, bVar.f) && Intrinsics.b(this.g, bVar.g) && Double.compare(this.h, bVar.h) == 0 && Double.compare(this.i, bVar.i) == 0;
    }

    public final int hashCode() {
        d dVar = this.a;
        int iHashCode = (dVar == null ? 0 : dVar.hashCode()) * 31;
        Checkpoint checkpoint = this.b;
        int iHashCode2 = (iHashCode + (checkpoint == null ? 0 : checkpoint.hashCode())) * 31;
        k kVar = this.c;
        int iHashCode3 = (iHashCode2 + (kVar == null ? 0 : kVar.hashCode())) * 31;
        Integer num = this.d;
        int iHashCode4 = (iHashCode3 + (num == null ? 0 : num.hashCode())) * 31;
        Double d = this.e;
        int iHashCode5 = (iHashCode4 + (d == null ? 0 : d.hashCode())) * 31;
        Integer num2 = this.f;
        int iHashCode6 = (iHashCode5 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Task task = this.g;
        return Double.hashCode(this.i) + d0.a(this.h, (iHashCode6 + (task != null ? task.a.hashCode() : 0)) * 31, 31);
    }

    public final String toString() {
        return "TaskStep(question=" + this.a + ", checkpoint=" + this.b + ", taskQuestionType=" + this.c + ", completedRoundUnits=" + this.d + ", roundProgress=" + this.e + ", totalRoundUnits=" + this.f + ", task=" + this.g + ", taskProgress=" + this.h + ", taskSequenceProgress=" + this.i + ")";
    }
}
