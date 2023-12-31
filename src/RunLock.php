<?php

namespace JustSecurityCheck\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class RunLock extends Command
{
    private $version = [];

    protected function configure()
    {
        $this->setName('run:check')
            ->setAliases(['r', 'run'])
            ->setDescription('Check which packages are older than a given date in your composer.lock')
            ->addOption('dev', 'd', InputOption::VALUE_NONE, 'If require-dev should be checked as well')
            ->addOption(
                'allow',
                ['exclude', 'E', 'e', 'A', 'a'],
                InputOption::VALUE_REQUIRED,
                'Exclude some vulnerabilities,'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $allow = [];
        if ($input->getOption('allow')) {
            $allow = array_fill_keys(explode(',', $input->getOption('allow')), 1);
        }

        $dir = getcwd() . '/';

        if (!file_exists($dir . 'composer.lock')) {
            $output->writeln('<fg=red>No composer.lock file found !</>');

            return 1;
        }

        $composerLock = file_get_contents($dir . 'composer.lock');

        $json = json_decode($composerLock, true);

        if (!array_key_exists('packages', $json)) {
            $output->writeln('<fg=red>There is no "require" !</>');
            return 1;
        }

        if ($input->getOption('dev')) {
            if (!array_key_exists('packages-dev', $json)) {
                $output->writeln('<fg=red>There is no "require-dev" !</>');
                return 1;
            }
        }

        $counter = 0;
        $counterPart = 0;
        $max = 50;
        $fullPackages = [];

        $this->parsePackages($json['packages'], $max, $fullPackages, $counter, $counterPart);

        if ($input->getOption('dev')) {
            $this->parsePackages($json['packages-dev'], $max, $fullPackages, $counter, $counterPart);
        }

        $packages = [];
        $advisoriesAll = [];
        foreach ($fullPackages as $partPackages) {
            if (count($partPackages) > 0) {
                $responseJson = file_get_contents(
                    'https://packagist.org/api/security-advisories/?packages[]=' .
                    implode('&packages[]=', array_keys($partPackages))
                );

                $packages = array_merge($packages, $partPackages);
                $advisoriesAll = array_merge($advisoriesAll, json_decode($responseJson, true)['advisories']);
            }
        }

        $allowRes = [];
        $result = [];
        foreach ($advisoriesAll as $key => $advisories) {
            $curVersion = $this->getFullVersion($packages[$key]);
            foreach ($advisories as $advisory) {
                if (array_key_exists('affectedVersions', $advisory)) {
                    $next = false;
                    $ranges = explode('|', $advisory['affectedVersions']);
                    foreach ($ranges as $range) {
                        $par1 = false;
                        $par2 = false;
                        $versiomArr = explode(',', $range);
                        $versionNotRange = (count($versiomArr) === 1);
                        foreach ($versiomArr as $versionStr) {
                            if (strpos($versionStr, '>=') !== false) {
                                $versionStr = str_replace('>=', '', $versionStr);
                                $par1 = ($curVersion >= $this->getFullVersion($versionStr));
                                if ($versionNotRange) {
                                    $par2 = true;
                                }
                            } elseif (strpos($versionStr, '>') !== false) {
                                $versionStr = str_replace('>', '', $versionStr);
                                $par1 = ($curVersion > $this->getFullVersion($versionStr));
                                if ($versionNotRange) {
                                    $par2 = true;
                                }
                            } elseif (strpos($versionStr, '<=') !== false) {
                                $versionStr = str_replace('<=', '', $versionStr);
                                $par2 = ($curVersion <= $this->getFullVersion($versionStr));
                                if ($versionNotRange) {
                                    $par1 = true;
                                }
                            } elseif (strpos($versionStr, '<') !== false) {
                                $versionStr = str_replace('<', '', $versionStr);
                                $par2 = ($curVersion < $this->getFullVersion($versionStr));
                                if ($versionNotRange) {
                                    $par1 = true;
                                }
                            }

                            if ($par1 && $par2) {
                                if (isset($allow[$key])) {
                                    $allowRes[$key] = $packages[$key];
                                } else {
                                    $result[$key] = $packages[$key];
                                }
                                break;
                            }
                        }
                        if ($par1 && $par2) {
                            $next = true;
                            break;
                        }
                    }
                    if ($next) {
                        break;
                    }
                }
            }
        }

        $output->writeln('');

        $vlna = count($allowRes);
        $vln = count($result);

        $vlnFormat = '<fg=green>' . ($vln + $vlna) . ' packages</>';

        if ($vlna > 0) {
            $output->writeln('<fg=magenta>Allowed:</>');
            foreach ($allowRes as $key => $val) {
                $link = ' https://packagist.org/packages/' . $key . '#' . $this->version[$key];
                $output->writeln('<fg=green>' . $key . '</> <fg=magenta>(v' . $val . ')</>' . $link);
            }
            $vlnFormat = '<fg=magenta>' . ($vln + $vlna) . ' packages</>';
            $output->writeln('<fg=magenta>--------------------------</>');
        }

        $res = 0;
        if ($vln > 0) {
            $res = 1;
            $output->writeln('<fg=red>Not allowed:</>');
            foreach ($result as $key => $val) {
                $link = ' https://packagist.org/packages/' . $key . '#' . $this->version[$key];
                $output->writeln('<fg=green>' . $key . '</> <fg=red>(v' . $val . ')</>' . $link);
            }
            $vlnFormat = '<fg=red>' . ($vln + $vlna) . ' packages</>';
            $output->writeln('<fg=red>--------------------------</>');
        }
        $output->writeln($vlnFormat . ' have known vulnerabilities.');

        return $res;
    }

    /**
     * @param string $str
     * @return int
     */
    private function getFullVersion($str)
    {
        $versionArr = explode('.', $str);

        $versionArr = array_pad($versionArr, 4, '000');

        $versionFull = '';
        foreach ($versionArr as & $item) {
            $versionFull .= str_pad($item, 3, '0', STR_PAD_LEFT);
        }

        return (int)$versionFull;
    }

    /**
     * @param array $packages
     * @param int $max
     * @param array $fullPackages
     * @param int $counter
     * @param int $counterPart
     * @return void
     */
    private function parsePackages($packages, $max, &$fullPackages, &$counter, &$counterPart)
    {
        foreach ($packages as $package) {
            $this->version[$package['name']] = $package['version'];
            $value = mb_eregi_replace("[^0-9.]", '', $package['version']);
            $fullPackages[$counterPart][$package['name']] = $value;

            if (++$counter === $max) {
                ++$counterPart;
                $counter = 0;
            }
        }
    }
}
