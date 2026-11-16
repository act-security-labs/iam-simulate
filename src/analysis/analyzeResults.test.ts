import { describe, expect, it } from 'vitest'
import type {
  IdentityAnalysis,
  IdentityEvaluationResult,
  RequestAnalysis,
  ResourceEvaluationResult
} from '../evaluate.js'
import type { Simulation } from '../simulation_engine/simulation.js'
import { runSimulation } from '../simulation_engine/simulationEngine.js'
import {
  getDenialReasons,
  getGrantReasons,
  isAllowedByIdentityPolicies,
  type RequestDenial,
  type RequestGrant
} from './analyzeResults.js'

describe('isAllowedByIdentityPolicies', () => {
  it('should return false if there is no identity analysis', () => {
    // Given a request analysis with no identity analysis
    const requestAnalysis: Partial<RequestAnalysis> = {
      result: 'ImplicitlyDenied',
      sameAccount: false
    }

    // When we analyze the request analysis
    const result = isAllowedByIdentityPolicies(requestAnalysis as any)

    // Then the result should be false
    expect(result).toBe(false)
  })

  it('should return true if the identity analysis result is Allowed', () => {
    // Given a request analysis with an identity analysis that is Allowed
    const requestAnalysis: Partial<Omit<RequestAnalysis, 'identityAnalysis'>> & {
      identityAnalysis?: Partial<IdentityAnalysis>
    } = {
      result: 'Allowed',
      sameAccount: true,
      identityAnalysis: {
        result: 'Allowed'
      }
    }

    // When we analyze the request analysis
    const result = isAllowedByIdentityPolicies(requestAnalysis as RequestAnalysis)

    // Then the result should be true
    expect(result).toBe(true)
  })
})

const getDenialReasonsTests: {
  name: string
  only?: true
  simulation: Simulation
  expected: RequestDenial[]
  expectedIdentityResult?: IdentityEvaluationResult
  expectedResourceResult?: ResourceEvaluationResult
}[] = [
  // Identity policy tests
  {
    name: 'implicit identity denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        denialType: 'Implicit'
      }
    ],
    expectedResourceResult: 'NotApplicable'
  },
  {
    name: 'explicit identity denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'DenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'DenyAll',
                Effect: 'Deny',
                Action: '*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'DenyPolicy',
        statementId: 'DenyAll',
        statementIndex: 1,
        denialType: 'Explicit'
      }
    ]
  },
  {
    name: 'explicit identity denial uses index when no sid',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'DenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Deny',
                Action: '*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'DenyPolicy',
        statementIndex: 1,
        denialType: 'Explicit'
      }
    ]
  },
  // Resource policy tests
  {
    name: 'service principal denial from non-matching resource policy',
    simulation: {
      request: {
        principal: 'cloudtrail.amazonaws.com',
        action: 's3:PutObject',
        resource: {
          resource: 'arn:aws:s3:::example-logs-bucket/other/log.gz',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: 'cloudtrail.amazonaws.com' },
            Action: 's3:PutObject',
            Resource: 'arn:aws:s3:::example-logs-bucket/AWSLogs/*'
          }
        ]
      }
    },
    expected: [
      {
        policyType: 'resource',
        denialType: 'Implicit'
      }
    ],
    expectedIdentityResult: 'NotApplicable',
    expectedResourceResult: 'ImplicitlyDenied'
  },
  {
    name: 'service principal denial without a resource policy',
    simulation: {
      request: {
        principal: 'cloudtrail.amazonaws.com',
        action: 's3:PutObject',
        resource: {
          resource: 'arn:aws:s3:::example-logs-bucket/other/log.gz',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'resource',
        denialType: 'Implicit'
      }
    ],
    expectedIdentityResult: 'NotApplicable',
    expectedResourceResult: 'ImplicitlyDenied'
  },
  {
    name: 'implicit resource denial for cross-account request',
    simulation: {
      request: {
        principal: 'arn:aws:iam::111111111111:user/Alice',
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::example_bucket/object.txt',
          accountId: '222222222222'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: []
      },
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'resource',
        denialType: 'Implicit'
      }
    ]
  },
  {
    name: 'explicit resource denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::example_bucket/object.txt',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'DenyAlice',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: '*'
          }
        ]
      },
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'resource',
        blocking: true,
        policyIdentifier: undefined,
        statementId: 'DenyAlice',
        statementIndex: 1,
        denialType: 'Explicit'
      }
    ]
  },
  // SCP tests
  {
    name: 'implicit SCP denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'RestrictiveSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: 'ec2:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'scp',
        blocking: true,
        identifier: 'ou-root',
        denialType: 'Implicit'
      }
    ]
  },
  {
    name: 'explicit SCP denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'DenySCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: '*',
                    Resource: '*'
                  },
                  {
                    Sid: 'DenyS3',
                    Effect: 'Deny',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'scp',
        blocking: true,
        policyIdentifier: 'DenySCP',
        statementId: 'DenyS3',
        statementIndex: 2,
        denialType: 'Explicit'
      }
    ]
  },
  // RCP tests
  {
    name: 'explicit RCP denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::example_bucket/object.txt',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'DenyRCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Sid: 'DenyS3Access',
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ]
    },
    expected: [
      {
        policyType: 'rcp',
        blocking: true,
        policyIdentifier: 'DenyRCP',
        statementId: 'DenyS3Access',
        statementIndex: 1,
        denialType: 'Explicit'
      }
    ]
  },
  // Permission Boundary tests
  {
    name: 'implicit permission boundary denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'ec2:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'pb',
        blocking: true,
        denialType: 'Implicit'
      }
    ]
  },
  {
    name: 'explicit permission boundary denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*'
              },
              {
                Sid: 'DenyS3InBoundary',
                Effect: 'Deny',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'pb',
        blocking: true,
        policyIdentifier: 'BoundaryPolicy',
        statementId: 'DenyS3InBoundary',
        statementIndex: 2,
        denialType: 'Explicit'
      }
    ]
  },
  // Endpoint Policy tests
  {
    name: 'implicit endpoint policy denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      vpcEndpointPolicies: [
        {
          name: 'EndpointPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'ec2:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'vpce',
        blocking: true,
        denialType: 'Implicit'
      }
    ]
  },
  {
    name: 'explicit endpoint policy denial',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      vpcEndpointPolicies: [
        {
          name: 'EndpointPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: '*',
                Resource: '*'
              },
              {
                Sid: 'DenyS3Endpoint',
                Effect: 'Deny',
                Principal: '*',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'vpce',
        blocking: true,
        policyIdentifier: 'EndpointPolicy',
        statementId: 'DenyS3Endpoint',
        statementIndex: 2,
        denialType: 'Explicit'
      }
    ]
  },
  // Edge cases
  {
    name: 'no denials when allowed',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: []
  },
  {
    name: 'multiple explicit deny statements from same policy',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'MultiDenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'DenyOne',
                Effect: 'Deny',
                Action: 's3:ListBucket',
                Resource: '*'
              },
              {
                Sid: 'DenyTwo',
                Effect: 'Deny',
                Action: 's3:*',
                Resource: 'arn:aws:s3:::example_bucket'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'MultiDenyPolicy',
        statementId: 'DenyOne',
        statementIndex: 1,
        denialType: 'Explicit'
      },
      {
        policyType: 'identity',
        policyIdentifier: 'MultiDenyPolicy',
        statementId: 'DenyTwo',
        statementIndex: 2,
        denialType: 'Explicit'
      }
    ]
  },
  {
    name: 'multiple OUs in SCP with only one denying',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'RootSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: '*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        },
        {
          orgIdentifier: 'ou-child',
          policies: [
            {
              name: 'ChildSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: 'ec2:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'scp',
        blocking: true,
        identifier: 'ou-child',
        denialType: 'Implicit'
      }
    ]
  },
  {
    name: 'multiple denials from different policy types',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'IdentityDenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'IdentityDeny',
                Effect: 'Deny',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'ResourceDeny',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: '*'
          }
        ]
      },
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'SCPDenyPolicy',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: '*',
                    Resource: '*'
                  },
                  {
                    Sid: 'SCPDeny',
                    Effect: 'Deny',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'RCPDenyPolicy',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Sid: 'RCPDeny',
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryDenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*'
              },
              {
                Sid: 'BoundaryDeny',
                Effect: 'Deny',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      vpcEndpointPolicies: [
        {
          name: 'EndpointDenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: '*',
                Resource: '*'
              },
              {
                Sid: 'EndpointDeny',
                Effect: 'Deny',
                Principal: '*',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ]
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'IdentityDenyPolicy',
        statementId: 'IdentityDeny',
        statementIndex: 1,
        denialType: 'Explicit'
      },
      {
        policyType: 'resource',
        statementId: 'ResourceDeny',
        statementIndex: 1,
        denialType: 'Explicit'
      },
      {
        policyType: 'scp',
        policyIdentifier: 'SCPDenyPolicy',
        statementId: 'SCPDeny',
        statementIndex: 2,
        denialType: 'Explicit'
      },
      {
        policyType: 'rcp',
        policyIdentifier: 'RCPDenyPolicy',
        statementId: 'RCPDeny',
        statementIndex: 1,
        denialType: 'Explicit'
      },
      {
        policyType: 'pb',
        policyIdentifier: 'BoundaryDenyPolicy',
        statementId: 'BoundaryDeny',
        statementIndex: 2,
        denialType: 'Explicit'
      },
      {
        policyType: 'vpce',
        policyIdentifier: 'EndpointDenyPolicy',
        statementId: 'EndpointDeny',
        statementIndex: 2,
        denialType: 'Explicit'
      }
    ]
  },
  {
    name: 'mixed blockers: implicit scp omitted when overall result is explicit',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::example_bucket/object.txt',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowIdentityPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:GetObject',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'ImplicitDenySCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: 'ec2:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*'
              },
              {
                Sid: 'BoundaryDenyS3',
                Effect: 'Deny',
                Action: 's3:GetObject',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'pb',
        blocking: true,
        policyIdentifier: 'BoundaryPolicy',
        statementId: 'BoundaryDenyS3',
        statementIndex: 2,
        denialType: 'Explicit'
      },
      {
        policyType: 'scp',
        blocking: true,
        identifier: 'ou-root',
        denialType: 'Implicit'
      }
    ]
  },
  {
    name: 'mixed blockers: implicit endpoint omitted when overall result is explicit',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowIdentityPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:ListBucket',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'DenySCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: '*',
                    Resource: '*'
                  },
                  {
                    Sid: 'SCPDenyS3',
                    Effect: 'Deny',
                    Action: 's3:ListBucket',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      vpcEndpointPolicies: [
        {
          name: 'EndpointPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'ec2:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'scp',
        blocking: true,
        policyIdentifier: 'DenySCP',
        statementId: 'SCPDenyS3',
        statementIndex: 2,
        denialType: 'Explicit'
      },
      {
        policyType: 'vpce',
        blocking: true,
        denialType: 'Implicit'
      }
    ]
  }
]

function jsonSort(a: any, b: any): number {
  return JSON.stringify(a).localeCompare(JSON.stringify(b))
}

describe('getDenialReasons', () => {
  for (const test of getDenialReasonsTests) {
    const testFn = test.only ? it.only : it
    testFn(`should correctly analyze denying policy statements: ${test.name}`, async () => {
      // Given a response to a simulation request
      const response = await runSimulation(test.simulation, {})
      if (response.resultType !== 'single') {
        throw new Error('Expected a single simulation result')
      }
      const requestAnalysis = response.result.analysis!

      // When we analyze the request analysis
      const result = getDenialReasons(requestAnalysis)

      // Then the result should match the expected denying statements
      expect(result.sort(jsonSort)).toEqual(test.expected.sort(jsonSort))
      if (test.expectedIdentityResult) {
        expect(requestAnalysis.identityAnalysis?.result).toEqual(test.expectedIdentityResult)
      }
      if (test.expectedResourceResult) {
        expect(requestAnalysis.resourceAnalysis?.result).toEqual(test.expectedResourceResult)
      }
    })
  }

  it('reports resource grants without identity grants for an allowed service principal', async () => {
    //Given a service principal allowed by a matching resource policy
    const response = await runSimulation(
      {
        request: {
          principal: 'cloudtrail.amazonaws.com',
          action: 's3:PutObject',
          resource: {
            resource: 'arn:aws:s3:::example-logs-bucket/AWSLogs/log.gz',
            accountId: '123456789012'
          },
          contextVariables: {}
        },
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { Service: 'cloudtrail.amazonaws.com' },
              Action: 's3:PutObject',
              Resource: 'arn:aws:s3:::example-logs-bucket/AWSLogs/*'
            }
          ]
        }
      },
      {}
    )
    if (response.resultType !== 'single') {
      throw new Error('Expected a single simulation result')
    }

    //When we inspect the result analysis and grants
    const analysis = response.result.analysis!
    const grants = getGrantReasons(analysis)

    //Then the identity layer is not applicable and the resource policy is the sole grant
    expect(analysis.identityAnalysis?.result).toEqual('NotApplicable')
    expect(getDenialReasons(analysis)).toEqual([])
    expect(grants).toEqual([{ policyType: 'resource', statementIndex: 1 }])
  })

  it('preserves explicit resource denials for service principals', async () => {
    //Given a service principal denied by a matching resource-policy statement
    const response = await runSimulation(
      {
        request: {
          principal: 'cloudtrail.amazonaws.com',
          action: 's3:PutObject',
          resource: {
            resource: 'arn:aws:s3:::example-logs-bucket/AWSLogs/log.gz',
            accountId: '123456789012'
          },
          contextVariables: {}
        },
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: {
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'DenyServiceWrite',
              Effect: 'Deny',
              Principal: { Service: 'cloudtrail.amazonaws.com' },
              Action: 's3:PutObject',
              Resource: 'arn:aws:s3:::example-logs-bucket/AWSLogs/*'
            }
          ]
        }
      },
      {}
    )
    if (response.resultType !== 'single') {
      throw new Error('Expected a single simulation result')
    }

    //When we inspect its denial reasons
    const analysis = response.result.analysis!
    const denials = getDenialReasons(analysis)

    //Then the resource statement is the only reported denial
    expect(analysis.identityAnalysis?.result).toEqual('NotApplicable')
    expect(denials).toEqual([
      {
        policyType: 'resource',
        policyIdentifier: undefined,
        statementId: 'DenyServiceWrite',
        statementIndex: 1,
        denialType: 'Explicit'
      }
    ])
  })
})

const getGrantReasonsTests: {
  name: string
  only?: true
  simulation: Simulation
  expected: RequestGrant[]
}[] = [
  {
    name: 'identity policy grant with named sid',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'identity policy grant without sid',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'cross-account resource policy grant returns both identity and resource grants',
    simulation: {
      request: {
        principal: 'arn:aws:iam::111111111111:user/Alice',
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::example_bucket/object.txt',
          accountId: '222222222222'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AllowCrossAccount',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::111111111111:root' },
            Action: 's3:GetObject',
            Resource: '*'
          }
        ]
      },
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'resource',
        statementId: 'AllowCrossAccount',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'multiple allow statements returns one entry per matching statement',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'MultiAllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowOne',
                Effect: 'Allow',
                Action: 's3:ListBucket',
                Resource: '*'
              },
              {
                Sid: 'AllowTwo',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: 'arn:aws:s3:::example_bucket'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'MultiAllowPolicy',
        statementId: 'AllowOne',
        statementIndex: 1
      },
      {
        policyType: 'identity',
        policyIdentifier: 'MultiAllowPolicy',
        statementId: 'AllowTwo',
        statementIndex: 2
      }
    ]
  },
  {
    name: 'explicitly denied request returns empty array',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'DenyPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'DenyAll',
                Effect: 'Deny',
                Action: '*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AllowAlice',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::123456789012:user/Alice' },
            Action: 's3:ListBucket',
            Resource: 'arn:aws:s3:::example_bucket'
          }
        ]
      },
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: []
  },
  {
    name: 'implicitly denied request returns empty array',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: []
  },
  {
    name: 'SCP grant',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'AllowSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Sid: 'AllowAll',
                    Effect: 'Allow',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-root',
        policyIdentifier: 'AllowSCP',
        statementId: 'AllowAll',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'RCP grant — default RCPFullAWSAccess allow is surfaced as a grant',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'DenyEC2RCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 'ec2:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ]
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'rcp',
        orgIdentifier: 'ou-root',
        policyIdentifier:
          'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'permission boundary grant',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3InBoundary',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'pb',
        policyIdentifier: 'BoundaryPolicy',
        statementId: 'AllowS3InBoundary',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'VPC endpoint policy grant',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      vpcEndpointPolicies: [
        {
          name: 'EndpointPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3Endpoint',
                Effect: 'Allow',
                Principal: '*',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'vpce',
        policyIdentifier: 'EndpointPolicy',
        statementId: 'AllowS3Endpoint',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'multiple allow statements in a single SCP policy come back separately',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'MultiAllowSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Sid: 'AllowListBucket',
                    Effect: 'Allow',
                    Action: 's3:ListBucket',
                    Resource: '*'
                  },
                  {
                    Sid: 'AllowAllS3',
                    Effect: 'Allow',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-root',
        policyIdentifier: 'MultiAllowSCP',
        statementId: 'AllowListBucket',
        statementIndex: 1
      },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-root',
        policyIdentifier: 'MultiAllowSCP',
        statementId: 'AllowAllS3',
        statementIndex: 2
      }
    ]
  },
  // No-Sid tests for new policy types
  {
    name: 'pb grant without sid uses only index',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      { policyType: 'identity', policyIdentifier: 'AllowPolicy', statementIndex: 1 },
      { policyType: 'pb', policyIdentifier: 'BoundaryPolicy', statementIndex: 1 }
    ]
  },
  {
    name: 'vpce grant without sid uses only index',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      vpcEndpointPolicies: [
        {
          name: 'EndpointPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      { policyType: 'identity', policyIdentifier: 'AllowPolicy', statementIndex: 1 },
      { policyType: 'vpce', policyIdentifier: 'EndpointPolicy', statementIndex: 1 }
    ]
  },
  {
    name: 'scp grant without sid uses only index',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'AllowSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      { policyType: 'identity', policyIdentifier: 'AllowPolicy', statementIndex: 1 },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-root',
        policyIdentifier: 'AllowSCP',
        statementIndex: 1
      }
    ]
  },
  // Multi-OU org scoping edge cases
  {
    name: 'multi-OU SCP: grants are collected from all OUs',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Sid: 'AllowS3', Effect: 'Allow', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'RootSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [{ Sid: 'AllowAllRoot', Effect: 'Allow', Action: 's3:*', Resource: '*' }]
              }
            }
          ]
        },
        {
          orgIdentifier: 'ou-child',
          policies: [
            {
              name: 'ChildSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  { Sid: 'AllowListChild', Effect: 'Allow', Action: 's3:ListBucket', Resource: '*' }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-root',
        policyIdentifier: 'RootSCP',
        statementId: 'AllowAllRoot',
        statementIndex: 1
      },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-child',
        policyIdentifier: 'ChildSCP',
        statementId: 'AllowListChild',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'multi-OU RCP: grants are collected from all OUs',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [{ Sid: 'AllowS3', Effect: 'Allow', Action: 's3:*', Resource: '*' }]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'DenyEC2Root',
              policy: {
                Version: '2012-10-17',
                Statement: [{ Effect: 'Deny', Principal: '*', Action: 'ec2:*', Resource: '*' }]
              }
            }
          ]
        },
        {
          orgIdentifier: 'ou-child',
          policies: [
            {
              name: 'DenyEC2Child',
              policy: {
                Version: '2012-10-17',
                Statement: [{ Effect: 'Deny', Principal: '*', Action: 'ec2:*', Resource: '*' }]
              }
            }
          ]
        }
      ]
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'rcp',
        orgIdentifier: 'ou-root',
        policyIdentifier:
          'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
        statementIndex: 1
      },
      {
        policyType: 'rcp',
        orgIdentifier: 'ou-child',
        policyIdentifier:
          'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'non-matching allow statements are not included in grants',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'MixedPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3ListBucket',
                Effect: 'Allow',
                Action: 's3:ListBucket',
                Resource: '*'
              },
              {
                Sid: 'AllowEC2',
                Effect: 'Allow',
                Action: 'ec2:DescribeInstances',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'MixedPolicy',
        statementId: 'AllowS3ListBucket',
        statementIndex: 1
      }
    ]
  },
  {
    name: 'multiple grant types: identity, SCP, and permission boundary',
    simulation: {
      request: {
        principal: 'arn:aws:iam::123456789012:user/Alice',
        action: 's3:ListBucket',
        resource: {
          resource: 'arn:aws:s3:::example_bucket',
          accountId: '123456789012'
        },
        contextVariables: {}
      },
      identityPolicies: [
        {
          name: 'AllowPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      permissionBoundaryPolicies: [
        {
          name: 'BoundaryPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'AllowS3InBoundary',
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-root',
          policies: [
            {
              name: 'AllowSCP',
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Sid: 'AllowAll',
                    Effect: 'Allow',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ],
      resourceControlPolicies: []
    },
    expected: [
      {
        policyType: 'identity',
        policyIdentifier: 'AllowPolicy',
        statementId: 'AllowS3',
        statementIndex: 1
      },
      {
        policyType: 'scp',
        orgIdentifier: 'ou-root',
        policyIdentifier: 'AllowSCP',
        statementId: 'AllowAll',
        statementIndex: 1
      },
      {
        policyType: 'pb',
        policyIdentifier: 'BoundaryPolicy',
        statementId: 'AllowS3InBoundary',
        statementIndex: 1
      }
    ]
  }
]

describe('getGrantReasons', () => {
  for (const test of getGrantReasonsTests) {
    const testFn = test.only ? it.only : it
    testFn(`should correctly identify granting policy statements: ${test.name}`, async () => {
      // Given a response to a simulation request
      const response = await runSimulation(test.simulation, {})
      if (response.resultType !== 'single') {
        throw new Error('Expected a single simulation result')
      }
      const requestAnalysis = response.result.analysis!

      // When we get the grant reasons
      const result = getGrantReasons(requestAnalysis)

      // Then the result should match the expected granting statements
      expect(result.sort(jsonSort)).toEqual(test.expected.sort(jsonSort))
    })
  }
})
