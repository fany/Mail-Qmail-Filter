use 5.014;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME               => 'Mail::Qmail::Filter',
    AUTHOR             => q{Martin Sluka <perl@sluka.de>},
    VERSION            => '2.0',
    EXE_FILES          => ['bin/qmail-deliverable'],
    LICENSE            => 'artistic_2',
    PL_FILES           => {},
    MIN_PERL_VERSION   => '5.036',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    BUILD_REQUIRES => {
        'Test::More' => '0',
    },
    PREREQ_PM => {
        'Capture::Tiny'               => 0,
        'Net::DNS::Resolver'          => 0,
        'Email::Valid'                => 0,
        'File::Scan::ClamAV'          => 0,
        'Mail::Address'               => 0,
        'Mail::DKIM::Verifier'        => 0,
        'Mail::DMARC::PurePerl'       => 0,
        'Mail::Header'                => 0,
        'Mail::Qmail::Queue::Message' => 0,
        'Mail::SpamAssassin'          => 0,
        'Mail::SPF'                   => 0,
        'Mo'                          => 0,
        'namespace::clean'            => 0,
        'Net::IP::Match::Trie'        => 1,
        'Net::SMTP'                   => 0,
        'Net::Domain'                 => 0,
        'Path::Tiny'                  => 0,
        'Qmail::Deliverable'          => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES    => 'Mail-Qmail-Filter-*' },

    PERM_DIR => '755',

    META_MERGE => {
        resources => {
            homepage   => 'https://github.com/fany/Mail-Qmail-Filter',
            repository => 'https://github.com/fany/Mail-Qmail-Filter.git',
        },
    },
);
