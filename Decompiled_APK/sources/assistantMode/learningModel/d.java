package assistantMode.learningModel;

/* loaded from: classes.dex */
public final class d {
    public final double a;
    public final double b;

    public d(double d, double d2) {
        this.a = d;
        this.b = d2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Double.compare(this.a, dVar.a) == 0 && Double.compare(this.b, dVar.b) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.b) + (Double.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ProbabilityPredictions(pCorrect=" + this.a + ", pGuess=" + this.b + ")";
    }
}
