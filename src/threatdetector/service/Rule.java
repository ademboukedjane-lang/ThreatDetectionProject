package threatdetector.service;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

public interface Rule  {
        boolean appliesTo(InputType type);

    RuleHit evaluate(ScanItem item);

}
